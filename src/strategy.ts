import { Strategy as PassportStrategy } from "passport-strategy";
import { strict as assert } from "assert";
import * as url from "url";
import { Profile, SAML, SamlConfig } from ".";
import {
  AuthenticateOptions,
  RequestWithUser,
  User,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";

export abstract class AbstractStrategy extends PassportStrategy {
  static readonly newSamlProviderOnConstruct: boolean;

  name: string;
  _signonVerify: VerifyWithRequest | VerifyWithoutRequest;
  _logoutVerify: VerifyWithRequest | VerifyWithoutRequest;
  _saml: SAML | undefined;
  _passReqToCallback?: boolean;

  constructor(
    options: SamlConfig,
    signonVerify: VerifyWithRequest,
    logoutVerify: VerifyWithRequest
  );
  constructor(
    options: SamlConfig,
    signonVerify: VerifyWithoutRequest,
    logoutVerify: VerifyWithoutRequest
  );
  constructor(options: SamlConfig, signonVerify: never, logoutVerify: never) {
    super();
    if (typeof options === "function") {
      throw new Error("Mandatory SAML options missing");
    }

    if (!signonVerify || typeof signonVerify != "function") {
      throw new Error("SAML authentication strategy requires a verify function");
    }

    // Customizing the name can be useful to support multiple SAML configurations at the same time.
    // Unlike other options, this one gets deleted instead of passed along.
    if (options.name) {
      this.name = options.name;
    } else {
      this.name = "saml";
    }

    this._signonVerify = signonVerify;
    this._logoutVerify = logoutVerify;
    if ((this.constructor as typeof Strategy).newSamlProviderOnConstruct) {
      this._saml = new SAML(options);
    }
    this._passReqToCallback = !!options.passReqToCallback;
  }

  authenticate(req: RequestWithUser, options: AuthenticateOptions): void {
    if (this._saml == null) {
      throw new Error("Can't get authenticate without a SAML provider defined.");
    }

    options.samlFallback = options.samlFallback || "login-request";
    const validateCallback = async ({
      profile,
      loggedOut,
    }: {
      profile: Profile | null;
      loggedOut: boolean;
    }) => {
      if (loggedOut) {
        if (profile != null) {
          // When logging out a user, use the consumer's `validate` function to check that
          // the `profile` associated with the logout request resolves to the same user
          // as the `profile` associated with the current session.
          const verified = async (logoutUser?: User) => {
            let userMatch = true;
            try {
              // Check to see if we are logging out the user that is currently logged in to craft a proper IdP response
              // It is up to the caller to return the same `User` as we have currently recorded as logged in for a successful logout

              assert.deepStrictEqual(req.user, logoutUser);
            } catch (err) {
              userMatch = false;
            }

            const RelayState = req.query?.RelayState || req.body?.RelayState;
            if (this._saml == null) {
              return this.error(
                new Error("Can't get logout response URL without a SAML provider defined.")
              );
            } else {
              this._saml.getLogoutResponseUrl(
                profile,
                RelayState,
                options,
                userMatch,
                redirectIfSuccess
              );
            }

            // Log out the current user no matter if we can verify the logged in user === logout requested user
            await new Promise((resolve, reject) => {
              req.logout((err) => {
                if (err) {
                  return reject(err);
                }
                resolve(undefined);
              });
            });
          };

          let logoutUser: User | undefined;
          if (this._passReqToCallback) {
            try {
              logoutUser = await new Promise((resolve, reject) => {
                (this._logoutVerify as VerifyWithRequest)(
                  req,
                  profile,
                  (err: Error | null, logoutUser?: User) => {
                    if (err) {
                      return reject(err);
                    }
                    resolve(logoutUser);
                  }
                );
              });
            } catch (err) {
              return this.error(err as Error);
            }
            await verified(logoutUser);
          } else {
            try {
              logoutUser = await new Promise((resolve, reject) => {
                (this._logoutVerify as VerifyWithoutRequest)(
                  profile,
                  (err: Error | null, logoutUser?: User) => {
                    if (err) {
                      return reject(err);
                    }
                    resolve(logoutUser);
                  }
                );
              });
            } catch (err) {
              return this.error(err as Error);
            }
            await verified(logoutUser);
          }
        } else {
          // If the `profile` object was null, this is just a logout acknowledgment, so we take no action
          return this.pass();
        }
      } else {
        const verified = (err: Error | null, user?: User, info?: unknown) => {
          if (err) {
            return this.error(err);
          }

          if (!user) {
            return this.fail(info, 401);
          }

          this.success(user, info);
        };

        if (this._passReqToCallback) {
          (this._signonVerify as VerifyWithRequest)(req, profile, verified);
        } else {
          (this._signonVerify as VerifyWithoutRequest)(profile, verified);
        }
      }
    };

    const redirectIfSuccess = (err: Error | null, url?: string) => {
      if (err) {
        this.error(err);
      } else if (url == null) {
        this.error(new Error("Invalid logout redirect URL."));
      } else {
        this.redirect(url);
      }
    };

    if (req.query?.SAMLResponse || req.query?.SAMLRequest) {
      const originalQuery = url.parse(req.url).query ?? "";
      this._saml
        .validateRedirectAsync(req.query, originalQuery)
        .then(validateCallback)
        .catch((err) => this.error(err));
    } else if (req.body?.SAMLResponse) {
      this._saml
        .validatePostResponseAsync(req.body)
        .then(validateCallback)
        .catch((err) => this.error(err));
    } else if (req.body?.SAMLRequest) {
      this._saml
        .validatePostRequestAsync(req.body)
        .then(validateCallback)
        .catch((err) => this.error(err));
    } else {
      const requestHandler = {
        "login-request": async () => {
          try {
            if (this._saml == null) {
              throw new Error("Can't process login request without a SAML provider defined.");
            }

            const RelayState =
              (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
            const host = req.headers && req.headers.host;
            if (this._saml.options.authnRequestBinding === "HTTP-POST") {
              const data = await this._saml.getAuthorizeFormAsync(RelayState, host);
              const res = req.res;
              res?.send(data);
            } else {
              // Defaults to HTTP-Redirect
              this.redirect(await this._saml.getAuthorizeUrlAsync(RelayState, host, options));
            }
          } catch (err) {
            this.error(err as Error);
          }
        },
        "logout-request": async () => {
          if (this._saml == null) {
            throw new Error("Can't process logout request without a SAML provider defined.");
          }

          try {
            const RelayState =
              (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
            this.redirect(
              await this._saml.getLogoutUrlAsync(req.user as Profile, RelayState, options)
            );
          } catch (err) {
            this.error(err as Error);
          }
        },
      }[options.samlFallback];

      if (typeof requestHandler !== "function") {
        return this.fail(401);
      }

      requestHandler();
    }
  }

  logout(req: RequestWithUser, callback: (err: Error | null, url?: string | null) => void): void {
    if (this._saml == null) {
      throw new Error("Can't logout without a SAML provider defined.");
    }
    const RelayState = (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
    this._saml
      .getLogoutUrlAsync(req.user as Profile, RelayState, {})
      .then((url) => callback(null, url))
      .catch((err) => callback(err));
  }

  protected _generateServiceProviderMetadata(
    decryptionCert: string | null,
    signingCert?: string | string[] | null
  ): string {
    if (this._saml == null) {
      throw new Error("Can't generate service provider metadata without a SAML provider defined.");
    }

    return this._saml.generateServiceProviderMetadata(decryptionCert, signingCert);
  }

  // This is redundant, but helps with testing
  error(err: Error): void {
    super.error(err);
  }
  redirect(url: string, status?: number): void {
    super.redirect(url, status);
  }
}

export class Strategy extends AbstractStrategy {
  static readonly newSamlProviderOnConstruct = true;

  generateServiceProviderMetadata(
    decryptionCert: string | null,
    signingCert?: string | string[] | null
  ): string {
    return this._generateServiceProviderMetadata(decryptionCert, signingCert);
  }
}
