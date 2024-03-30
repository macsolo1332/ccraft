// handler
import { HfInference } from "@huggingface/inference";
import { NextApiRequest, NextApiResponse } from "next";
import { NextResponse } from "next/server";

const HF_ACCESS_TOKEN = "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";

const inference = new HfInference(HF_ACCESS_TOKEN);

export const POST = async (req: Request) => {
  const requestJson = await req.json();
  const { text, lang } = requestJson;
  console.log(requestJson);

  // Map the languages to the correct models
  const languageModels = {
    "en-es": "Helsinki-NLP/opus-mt-en-es",
    "en-de": "Helsinki-NLP/opus-mt-en-de",
    "en-fr": "Helsinki-NLP/opus-mt-en-fr",
    "en-hi": "Helsinki-NLP/opus-mt-en-hi",
    "en-ml": "Helsinki-NLP/opus-mt-en-ml",

    // Add more models as needed
  };

  const translationResponse = await inference.translation({
    model: languageModels[lang], // Select the model based on the language
    inputs: text,
  });
  console.log('transilation response ',translationResponse)
  return NextResponse.json({
    translationResponse
  }, {
    status: 200
  })
}

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    // Process a POST request
  } else {
    // Handle any other HTTP method
  }
}
