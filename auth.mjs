
import { getDatabase } from "@netlify/database";
import {
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  createHash,
  timingSafeEqual
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const COOKIE = "__Host-fabi_session";
const SESSION_DAYS = 30;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extra
    }
  });
}

function getCookie(request) {
  const cookies = request.headers.get("cookie") || "";
  const item = cookies.split(";").find(
    value => value.trim().startsWith(COOKIE + "=")
  );
  return item ? item.trim().slice(COOKIE.length + 1) : "";
}

function cookieHeader(token, maxAge = SESSION_DAYS * 86400) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function hashToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function sameSecret(a, b) {
  if (!a || !b) return false;

  const first = Buffer.from(a);
  const second = Buffer.from(b);

  return first.length === second.length &&
    timingSafeEqual(first, second);
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const key = await scrypt(password, salt, 64);

  return `scrypt$${salt}$${Buffer.from(key).toString("hex")}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, salt, original] = stored.split("$");

    if (algorithm !== "scrypt" || !salt || !original) {
      return false;
    }

    const key = await scrypt(password, salt, 64);
    const expected = Buffer.from(original, "hex");
    const actual = Buffer.from(key);

    return expected.length === actual.length &&
      timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

async function createSession(client, accountId) {
  const token = randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);

  await client.query(
    `INSERT INTO sessions (id, account_id, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '30 days')`,
    [tokenHash, accountId]
  );

  return token;
}

export default async function handler(request) {
  try {
    const db = getDatabase();

    // Consultar sesión
    if (request.method === "GET") {
      const token = getCookie(request);

      if (!token) {
        return json({ authenticated: false });
      }

      const tokenHash = hashToken(token);

      const rows = await db.sql`
        SELECT a.id, a.username, a.email, a.role
        FROM sessions s
        JOIN accounts a ON a.id = s.account_id
        WHERE s.id = ${tokenHash}
          AND s.expires_at > NOW()
        LIMIT 1
      `;

      if (!rows.length) {
        return json({ authenticated: false });
      }

      return json({
        authenticated: true,
        account: rows[0]
      });
    }

    if (request.method !== "POST") {
      return json({ error: "Método no permitido" }, 405);
    }

    const body = await request.json();
    const action = body.action;

    // Registro público
    if (action === "register") {
      const username = String(body.username || "").trim();
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const ownerKey = String(body.ownerKey || "");

      if (
        username.length < 3 ||
        username.length > 24 ||
        !/^[a-zA-Z0-9_]+$/.test(username)
      ) {
        return json({ error: "Nombre de usuario inválido" }, 400);
      }

      if (
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      ) {
        return json({ error: "Correo inválido" }, 400);
      }

      if (password.length < 10 || password.length > 128) {
        return json({
          error: "La contraseña debe tener entre 10 y 128 caracteres"
        }, 400);
      }

      const ownerEmail = (
        process.env.OWNER_EMAIL || ""
      ).trim().toLowerCase();

      const ownerSetupKey = process.env.OWNER_SETUP_KEY || "";

      const isOwnerEmail = ownerEmail && email === ownerEmail;

      if (isOwnerEmail &&
          !sameSecret(ownerKey, ownerSetupKey)) {
        return json({
          error: "La llave privada no es válida"
        }, 403);
      }

      const role = isOwnerEmail ? "owner" : "user";
      const passwordHash = await hashPassword(password);
      const accountId = randomUUID();

      const client = await db.pool.connect();

      try {
        await client.query("BEGIN");

        if (role === "owner") {
          await client.query(
            "SELECT pg_advisory_xact_lock(82415031)"
          );

          const existingOwner = await client.query(
            "SELECT id FROM accounts WHERE role = 'owner' LIMIT 1"
          );

          if (existingOwner.rows.length) {
            await client.query("ROLLBACK");

            return json({
              error: "El propietario ya está registrado"
            }, 409);
          }
        }

        const inserted = await client.query(
          `INSERT INTO accounts
           (id, username, email, password_hash, role)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, username, email, role`,
          [accountId, username, email, passwordHash, role]
        );

        const token = await createSession(client, accountId);

        await client.query("COMMIT");

        return json({
          success: true,
          account: inserted.rows[0]
        }, 201, {
          "Set-Cookie": cookieHeader(token)
        });

      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    }

    // Inicio de sesión
    if (action === "login") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");

      const rows = await db.sql`
        SELECT id, username, email, password_hash, role
        FROM accounts
        WHERE email = ${email}
        LIMIT 1
      `;

      if (
        !rows.length ||
        !(await verifyPassword(password, rows[0].password_hash))
      ) {
        return json({
          error: "Correo o contraseña incorrectos"
        }, 401);
      }

      const account = rows[0];
      const token = randomBytes(32).toString("base64url");
      const tokenHash = hashToken(token);

      await db.sql`
        INSERT INTO sessions (id, account_id, expires_at)
        VALUES (
          ${tokenHash},
          ${account.id},
          NOW() + INTERVAL '30 days'
        )
      `;

      return json({
        success: true,
        account: {
          id: account.id,
          username: account.username,
          email: account.email,
          role: account.role
        }
      }, 200, {
        "Set-Cookie": cookieHeader(token)
      });
    }

    // Cerrar sesión
    if (action === "logout") {
      const token = getCookie(request);

      if (token) {
        await db.sql`
          DELETE FROM sessions
          WHERE id = ${hashToken(token)}
        `;
      }

      return json({
        success: true,
        message: "Sesión cerrada"
      }, 200, {
        "Set-Cookie": cookieHeader("", 0)
      });
    }

    return json({ error: "Acción desconocida" }, 400);

  } catch (error) {
    console.error("AUTH ERROR:", error);

    if (error.code === "23505") {
      return json({
        error: "El correo o nombre de usuario ya está registrado"
      }, 409);
    }

    return json({
      error: "Error interno de autenticación"
    }, 500);
  }
}
