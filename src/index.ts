import { getApiKey } from "./adminApiClient";
import { sendMessage } from "./messagesClient";

async function main() {
  // Example: retrieve API key metadata via Admin API
  const apiKeyId = process.env.API_KEY_ID;
  if (apiKeyId) {
    console.log(`Fetching API key info for: ${apiKeyId}`);
    const keyInfo = await getApiKey(apiKeyId);
    console.log("API Key info:", JSON.stringify(keyInfo, null, 2));
  }

  // Example: send a message via the Messages API
  const reply = await sendMessage("Hello, world");
  console.log("Claude says:", reply);
}

main().catch(console.error);
