import { NextResponse } from "next/server";
import { validateApiKey, getProviderConnections } from "@/lib/localDb";
import { backfillCodexEmails } from "@/lib/oauth/providers";

// GET /api/providers/client - List all connections for client (includes sensitive fields for sync)
export async function GET(request) {
  try {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return NextResponse.json({ error: "Missing API key" }, { status: 401 });
    }

    const apiKey = authHeader.slice(7);
    const isValid = await validateApiKey(apiKey);
    if (!isValid) {
      return NextResponse.json({ error: "Invalid API key" }, { status: 401 });
    }

    await backfillCodexEmails();
    const connections = await getProviderConnections();
    
    // Include sensitive fields for sync to cloud (only accessible from same origin)
    const clientConnections = connections.map(c => ({
      ...c,
      // Don't hide sensitive fields here since this is for internal sync
    }));

    return NextResponse.json({ connections: clientConnections });
  } catch (error) {
    console.log("Error fetching providers for client:", error);
    return NextResponse.json({ error: "Failed to fetch providers" }, { status: 500 });
  }
}
