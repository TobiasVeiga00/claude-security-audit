// Sends an unbounded, unsanitised user prompt straight to the model.
import OpenAI from "openai";

const client = new OpenAI();

export async function ask(userPrompt) {
  return client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: userPrompt }],
  });
}
