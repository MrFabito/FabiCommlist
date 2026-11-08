
import { getStore } from "@netlify/blobs";

export default async function handler(request) {
  if (request.method !== "GET") {
    return new Response("Método no permitido", { status: 405 });
  }

  try {
    const store = getStore("fabicommlist-accounts");

    const test = {
      ok: true,
      checkedAt: new Date().toISOString()
    };

    await store.set("system/check", JSON.stringify(test));

    const saved = await store.get("system/check", {
      type: "json",
      consistency: "strong"
    });

    return Response.json({
      success: saved?.ok === true,
      storage: "Netlify Blobs"
    });
  } catch (error) {
    console.error(error);

    return Response.json(
      { success: false, message: "Error conectando con Blobs" },
      { status: 500 }
    );
  }
}
