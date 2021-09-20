import { Strategy as PassportStrategy } from "passport-strategy";
import { SAML } from "../node-saml";
import * as url from "url";
import {
  AuthenticateOptions,
  RequestWithUser,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";
import { Profile } from "./types";

export abstract class AbstractStrategy extends PassportStrategy {
  static readonly newSamlProviderOnConstruct: boolean;

  name: string;
  _verify: VerifyWithRequest | VerifyWithoutRequest;
  _saml: SAML | undefined;
  _passReqToCallback?: boolean;

  constructor(options: SamlConfig, verify: VerifyWithRequest);
  constructor(options: SamlConfig, verify: VerifyWithoutRequest);
  constructor(options: SamlConfig, verify: never) {
    super();
    if (typeof options === "function") {
      throw new Error("Mandatory SAML options missing");
    }

    if (!verify) {
      throw new Error("SAML authentication strategy requires a verify function");
    }

    // Customizing the name can be useful to support multiple SAML configurations at the same time.
    // Unlike other options, this one gets deleted instead of passed along.
    if (options.name) {
      this.name = options.name;
    } else {
      this.name = "saml";
    }

    this._verify = verify;
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
    const validateCallback = ({
      profile,
      loggedOut,
    }: {
      profile?: Profile | null;
      loggedOut?: boolean;
    }) => {
      if (loggedOut) {
        req.logout();
        if (profile) {
          if (this._saml == null) {
            throw new Error("Can't get logout response URL without a SAML provider defined.");
          }

          const RelayState =
            (req.query && req.query.RelayState) || (req.body && req.body.RelayState);
          return this._saml.getLogoutResponseUrl(profile, RelayState, options, redirectIfSuccess);
        }
        return this.pass();
      }

      const verified = (
        err: Error | null,
        user?: Record<string, unknown>,
        info?: Record<string, unknown>
      ) => {
        if (err) {
          return this.error(err);
        }

        if (!user) {
          return this.fail(info, 401);
        }

        this.success(user, info);
      };

      if (this._passReqToCallback) {
        (this._verify as VerifyWithRequest)(req, profile, verified);
      } else {
        (this._verify as VerifyWithoutRequest)(profile, verified);
      }
    };

    const redirectIfSuccess = (err: Error | null, url?: string | null) => {
      if (err) {
        this.error(err);
      } else {
        this.redirect(url!);
      }
    };

    if (req.query && (req.query.SAMLResponse || req.query.SAMLRequest)) {
      const originalQuery = url.parse(req.url).query;
      this._saml
        .validateRedirectAsync(req.query, originalQuery)
        .then(validateCallback)
        .catch((err) => this.error(err));
    } else if (req.body && req.body.SAMLResponse) {
      this._saml
        .validatePostResponseAsync(req.body)
        .then(validateCallback)
        .catch((err) => this.error(err));
    } else if (req.body && req.body.SAMLRequest) {
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
              const res = req.res!;
              res.send(data);
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
    signingCert?: string | null
  ): string {
    if (this._saml == null) {
      throw new Error("Can't generate service provider metadata without a SAML provider defined.");
    }

    return this._saml.generateServiceProviderMetadata(decryptionCert, signingCert);
  }

  // This is reduntant, but helps with testing
  error(err: Error): void {
    super.error(err);
  }
}

export class Strategy extends AbstractStrategy {
  static readonly newSamlProviderOnConstruct = true;

  generateServiceProviderMetadata(
    decryptionCert: string | null,
    signingCert?: string | null
  ): string {
    return this._generateServiceProviderMetadata(decryptionCert, signingCert);
  }
}
