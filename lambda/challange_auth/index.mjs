
import  crypto from "crypto";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
const client = new SESClient({ region: "ap-northeast-1"});

const createSendEmailCommand = (toAddress, fromAddress, code) => {
  return new SendEmailCommand({
    Destination: {
      /* required */
      CcAddresses: [
        /* more items */
      ],
      ToAddresses: [
        toAddress,
        /* more To-email addresses */
      ],
    },
    Message: {
      /* required */
      Body: {
        /* required */
        Text: {
          Charset: "UTF-8",
          Data: `verification code ${code}`,
        },
      },
      Subject: {
        Charset: "UTF-8",
        Data: "EMAIL_SUBJECT",
      },
    },
    Source: fromAddress,
    ReplyToAddresses: [
      /* more items */
    ],
  });
};


export const handler = async (event) => {
    
    let verificationCode = ""; 
    if (event.request.session.length === 2) {

      verificationCode = crypto.randomBytes(3).toString('hex');
      const sendEmailCommand = createSendEmailCommand(
        process.env.TO_ADDRESS,
        process.env.FROM_ADDRESS,
        verificationCode
      );
    
      try {
         await client.send(sendEmailCommand);
      } catch (e) {
        console.error(e);
        return e;
      }
    } else {
        //if the user makes a mistake, we utilize the verification code from the previous session so that the user can retry.
        const previousChallenge = event.request.session.slice(-1)[0];
        verificationCode = previousChallenge.challengeMetadata;
    }

    event.response.privateChallengeParameters = {
        "verificationCode": verificationCode
    };

    //add it to session, so its available during the next invocation.
    event.response.challengeMetadata = verificationCode;

    return event;

};