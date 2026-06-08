import https from "https";

export interface ApiKeyResponse {
  id: string;
  type: string;
  name: string;
  status: string;
  created_at: string;
  last_used_at: string | null;
  partial_key_hint: string;
  workspace_id: string | null;
  created_by: {
    id: string;
    type: string;
  };
}

/**
 * Retrieves an API key's metadata from the Anthropic Admin API.
 * Requires ANTHROPIC_ADMIN_API_KEY environment variable.
 */
export function getApiKey(apiKeyId: string): Promise<ApiKeyResponse> {
  const adminApiKey = process.env.ANTHROPIC_ADMIN_API_KEY;
  if (!adminApiKey) {
    throw new Error("ANTHROPIC_ADMIN_API_KEY environment variable is not set");
  }

  return new Promise((resolve, reject) => {
    const options: https.RequestOptions = {
      hostname: "api.anthropic.com",
      path: `/v1/organizations/api_keys/${encodeURIComponent(apiKeyId)}`,
      method: "GET",
      headers: {
        "anthropic-version": "2023-06-01",
        "X-Api-Key": adminApiKey,
        "Content-Type": "application/json",
      },
    };

    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed as ApiKeyResponse);
          } else {
            reject(new Error(`Admin API error ${res.statusCode}: ${body}`));
          }
        } catch {
          reject(new Error(`Failed to parse response: ${body}`));
        }
      });
    });

    req.on("error", reject);
    req.end();
  });
}
