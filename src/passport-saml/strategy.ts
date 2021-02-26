import { Strategy as PassportStrategy } from "passport-strategy";
import * as saml from "./saml";
import * as url from "url";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  RequestWithUser,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";
import { Profile } from "./types";

class Strategy extends PassportStrategy {
  name: string;
  _verify: VerifyWithRequest | VerifyWithoutRequest;
  _saml: saml.SAML;
  _passReqToCallback?: boolean;

  constructor(options: SamlConfig, verify: VerifyWithRequest);
  constructor(options: SamlConfig, verify: VerifyWithoutRequest);
  constructor(options: SamlConfig, verify: never) {
    super();
    if (typeof options == "function") {
      verify = options;
      options = {};
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
    this._saml = new saml.SAML(options);
    this._passReqToCallback = !!options.passReqToCallback;
  }

  authenticate(req: RequestWithUser, options: AuthenticateOptions): void {
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
          req.samlLogoutRequest = profile;
          return this._saml.getLogoutResponseUrl(req, options, redirectIfSuccess);
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
            if (this._saml.options.authnRequestBinding === "HTTP-POST") {
              const data = await this._saml.getAuthorizeFormAsync(req);
              const res = req.res!;
              res.send(data);
            } else {
              // Defaults to HTTP-Redirect
              this.redirect(await this._saml.getAuthorizeUrlAsync(req, options));
            }
          } catch (err) {
            this.error(err);
          }
        },
        "logout-request": async () => {
          try {
            this.redirect(await this._saml.getLogoutUrlAsync(req, options));
          } catch (err) {
            this.error(err);
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
    this._saml
      .getLogoutUrlAsync(req, {})
      .then((url) => callback(null, url))
      .catch((err) => callback(err));
  }

  generateServiceProviderMetadata(
    decryptionCert: string | null,
    signingCert?: string | null
  ): string {
    return this._saml.generateServiceProviderMetadata(decryptionCert, signingCert);
  }
}

export = Strategy;
