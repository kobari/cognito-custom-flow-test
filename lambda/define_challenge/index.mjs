export const handler = async (event, context, callback) => {
  // Confirm the user
  //event.response.autoConfirmUser = true;

  // Set the email as verified if it is in the request
  //if (event.request.userAttributes.hasOwnProperty("email")) {
  //  event.response.autoVerifyEmail = true;
  //}
  console.log(event.request);
  if (event.request.session && event.request.session.length === 1
            && event.request.session[0].challengeName === 'SRP_A'
            && event.request.session[0].challengeResult === true) {
            //SRP_A is the first challenge, this will be implemented by cognito. Set next challenge as PASSWORD_VERIFIER.
            event.response.issueTokens = false;
            event.response.failAuthentication = false;
            event.response.challengeName = 'PASSWORD_VERIFIER';
            
  } else if (event.request.session && event.request.session.length === 2
            && event.request.session[1].challengeName === 'PASSWORD_VERIFIER'
            && event.request.session[1].challengeResult === true) {
            console.log(event.request.session);

            //If password verification is successful then set next challenge as CUSTOM_CHALLENGE.
            event.response.issueTokens = false;
            event.response.failAuthentication = false;
            event.response.challengeName = 'CUSTOM_CHALLENGE';
            
  // }else if (event.request.session && event.request.session.length >= 5
  //           && event.request.session.slice(-1)[0].challengeName === 'CUSTOM_CHALLENGE'
  //           && event.request.session.slice(-1)[0].challengeResult === false) {
  //           //The user has exhausted 3 attempts to enter correct otp.
  //           event.response.issueTokens = false;
  //           event.response.failAuthentication = true;
            
  } else if (event.request.session  && event.request.session.slice(-1)[0].challengeName === 'CUSTOM_CHALLENGE'
      && event.request.session.slice(-1)[0].challengeResult === true) {
      //User entered the correct OTP. Issue tokens.
      event.response.issueTokens = true;
      event.response.failAuthentication = false;
      
  } else {
      //user did not provide a correct answer yet.
      event.response.issueTokens = false;
      event.response.failAuthentication = false;
      event.response.challengeName = 'CUSTOM_CHALLENGE';
  }
  
  console.log(event);
  //return event;
  callback(null, event);
};
