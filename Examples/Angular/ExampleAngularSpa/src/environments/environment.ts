// This file can be replaced during build by using the `fileReplacements` array.
// `ng build --prod` replaces `environment.ts` with `environment.prod.ts`.
// The list of file replacements can be found in `angular.json`.

export const environment = {
    production: false,
    samlSsoUrl: 'https://67e2-188-250-240-31.ngrok-free.app/Saml/InitiateSingleSignOn',
    samlSloUrl: 'https://67e2-188-250-240-31.ngrok-free.app/Saml/InitiateSingleLogout',
    samlAuthUrl: 'https://67e2-188-250-240-31.ngrok-free.app/api/Authorization',
    apiUrl: 'https://67e2-188-250-240-31.ngrok-free.app/api',
    // samlSsoUrl: '/Saml/InitiateSingleSignOn',
    // samlSloUrl: '/Saml/InitiateSingleLogout',
    // samlAuthUrl: '/api/Authorization',
    // apiUrl: '/api',
    jwtCookieName: 'JWT'
  };
  
  /*
   * For easier debugging in development mode, you can import the following file
   * to ignore zone related error stack frames such as `zone.run`, `zoneDelegate.invokeTask`.
   *
   * This import should be commented out in production mode because it will have a negative impact
   * on performance if an error is thrown.
   */
  // import 'zone.js/dist/zone-error';  // Included with Angular CLI.
  