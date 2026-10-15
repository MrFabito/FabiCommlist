exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Método no permitido" })
    };
  }

  const {
    GITHUB_TOKEN,
    GITHUB_OWNER,
    GITHUB_REPO,
    GITHUB_BRANCH,
    ADMIN_PASSWORD
  } = process.env;

  if (
    !GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO ||
    !GITHUB_BRANCH || !ADMIN_PASSWORD
  ) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Falta configurar las variables de Netlify"
      })
    };
  }

  try {
    const body = JSON.parse(event.body || "{}");

    if (
      typeof body.password !== "string" ||
      body.password !== ADMIN_PASSWORD
    ) {
      return {
        statusCode: 401,
        body: JSON.stringify({ error: "Contraseña incorrecta" })
      };
    }

    if (!Array.isArray(body.levels)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Lista de niveles inválida" })
      };
    }

    const api =
      `https://api.github.com/repos/${encodeURIComponent(GITHUB_OWNER)}` +
      `/${encodeURIComponent(GITHUB_REPO)}/contents/levels.json`;

    const headers = {
      "Authorization": `Bearer ${GITHUB_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json"
    };

    const current = await fetch(
      `${api}?ref=${encodeURIComponent(GITHUB_BRANCH)}`,
      { headers }
    );

    if (!current.ok) {
      throw new Error("No se pudo consultar levels.json en GitHub");
    }

    const file = await current.json();

    const content = Buffer.from(
      JSON.stringify({ levels: body.levels }, null, 2),
      "utf8"
    ).toString("base64");

    const saved = await fetch(api, {
      method: "PUT",
      headers,
      body: JSON.stringify({
        message: "Actualizar FabiCommlist",
        content,
        sha: file.sha,
        branch: GITHUB_BRANCH
      })
    });

    if (!saved.ok) {
      throw new Error("GitHub rechazó la actualización");
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: "Niveles guardados en GitHub"
      })
    };
  } catch (error) {
    console.error(error.message);

    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "No se pudieron publicar los niveles"
      })
    };
  }
};
