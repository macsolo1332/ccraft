import { db } from '@/db'
import { getKindeServerSession } from '@kinde-oss/kinde-auth-nextjs/server'
import {
  createUploadthing,
  type FileRouter,
} from 'uploadthing/next'

import { PDFLoader } from 'langchain/document_loaders/fs/pdf'
import { OpenAIEmbeddings } from 'langchain/embeddings/openai'
import { PineconeStore } from 'langchain/vectorstores/pinecone'
import { getPineconeClient } from '@/lib/pinecone'
// import { getUserSubscriptionPlan } from '@/lib/stripe'
import { PLANS } from '@/config/stripe'

const f = createUploadthing()

const middleware = async () => {
  const { getUser } = getKindeServerSession()
  const user = getUser()

  if (!user || !user.id) throw new Error('Unauthorized')

  // const subscriptionPlan = await getUserSubscriptionPlan()

  return {
    //  subscriptionPlan, 
    userId: user.id }
}

const onUploadComplete = async ({
  metadata,
  file,
}: {
  metadata: Awaited<ReturnType<typeof middleware>>
  file: {
    key: string
    name: string
    url: string
  }
}) => {
  const isFileExist = await db.file.findFirst({
    where: {
      key: file.key,
    },
  })

  if (isFileExist) return

  const createdFile = await db.file.create({
    data: {
      key: file.key,
      name: file.name,
      userId: metadata.userId,
      url: `https://utfs.io/f/${file.key}`,
      uploadStatus: 'PROCESSING',
    },
  })

  try {
    const response = await fetch(
      `https://utfs.io/f/${file.key}`
    )

    const blob = await response.blob()

    const loader = new PDFLoader(blob)

    const pageLevelDocs = await loader.load()

    const pagesAmt = pageLevelDocs.length

    // const { subscriptionPlan } = metadata
    // const { isSubscribed } = subscriptionPlan

    // const isProExceeded =
    //   pagesAmt >
    //   PLANS.find((plan) => plan.name === 'Pro')!.pagesPerPdf
    // const isFreeExceeded =
    //   pagesAmt >
    //   PLANS.find((plan) => plan.name === 'Free')!
    //     .pagesPerPdf

    // if (
    //   (isSubscribed && isProExceeded) ||
    //   (!isSubscribed && isFreeExceeded)
    // ) {
    //   await db.file.update({
    //     data: {
    //       uploadStatus: 'FAILED',
    //     },
    //     where: {
    //       id: createdFile.id,
    //     },
    //   })
    // }

    // vectorize and index entire document
    const pinecone = await getPineconeClient()
    const pineconeIndex = pinecone.Index('coursecraft')

    const embeddings = new OpenAIEmbeddings({
      openAIApiKey: process.env.OPENAI_API_KEY,
    })

    await PineconeStore.fromDocuments(
      pageLevelDocs,
      embeddings,
      {
        pineconeIndex,
        namespace: createdFile.id,
      }
    )

    await db.file.update({
      data: {
        uploadStatus: 'SUCCESS',
      },
      where: {
        id: createdFile.id,
      },
    })
  } catch (err) {
    await db.file.update({
      data: {
        uploadStatus: 'FAILED',
      },
      where: {
        id: createdFile.id,
      },
    })
  }

  

  //malware detection

     
  const options = {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      url: `https://utfs.io/f/${file.url}`,
      apikey: '4f714c4d7c793cc8676a7fd24ab22317059b10ae65b51ae0f28d66e3a833d8a4'
    })
  };
  
  const options1 = {
    method: 'GET',
    headers: {
      accept: 'application/json'
    }
  };
  
  let intervalId: NodeJS.Timeout; 
  
  try {
    const response = await fetch('https://www.virustotal.com/vtapi/v2/url/scan', options);
  
    if (response.ok) {
      const jsonResponse = await response.json();
      const scanId = jsonResponse.scan_id;
  
      intervalId = setInterval(async () => {
        const response1 = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=4f714c4d7c793cc8676a7fd24ab22317059b10ae65b51ae0f28d66e3a833d8a4&resource=${scanId}&allinfo=false&scan=0`, options1);
        const jsonResponse1 = await response1.json();
  
        console.log('Latest detected responses:', jsonResponse1);
        console.log('Malware detected:', jsonResponse1.positives);
  
        
        if (jsonResponse1.response_code === 1) {
          clearInterval(intervalId);
          console.log('Interval stopped due to response_code 0.');
        }
        if (jsonResponse1.positives !== 0){
          await db.file.update({
            data: {
              uploadStatus: 'FAILED',
            },
            where: {
              id: createdFile.id,
            },
          })
        }
      }, 3000);

     
    }
  
  } catch (err) {
    console.error('Error:', err);
  }

 
  
  
}



export const ourFileRouter = {
  freePlanUploader: f({ pdf: { maxFileSize: '4MB' } })
    .middleware(middleware)
    .onUploadComplete(onUploadComplete),
  proPlanUploader: f({ pdf: { maxFileSize: '16MB' } })
    .middleware(middleware)
    .onUploadComplete(onUploadComplete),
} satisfies FileRouter

export type OurFileRouter = typeof ourFileRouter
