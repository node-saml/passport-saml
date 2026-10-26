import { AbstractStrategy } from "./strategy";
import type { Request } from "express";
import {
  AuthenticateOptions,
  MultiStrategyConfig,
  RequestWithUser,
  PassportSamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";
import { SAML } from "@node-saml/node-saml";

export class MultiSamlStrategy extends AbstractStrategy {
  static readonly newSamlProviderOnConstruct = false;
  _options: PassportSamlConfig & MultiStrategyConfig;

  constructor(
    options: MultiStrategyConfig,
    signonVerify: VerifyWithRequest,
    logoutVerify: VerifyWithRequest,
  );
  constructor(
    options: MultiStrategyConfig,
    signonVerify: VerifyWithoutRequest,
    logoutVerify: VerifyWithoutRequest,
  );
  constructor(options: MultiStrategyConfig, signonVerify: never, logoutVerify: never) {
    if (!options || typeof options.getSamlOptions !== "function") {
      throw new Error("Please provide a getSamlOptions function");
    }

    // Force the type on this since we've disabled `newOnConstruct`
    // so the `SAML` constructor will not be called at this time
    // and there are defaults for all `strategy`-required options.
    const samlConfig = {
      ...options,
    } as PassportSamlConfig & MultiStrategyConfig;

    super(samlConfig, signonVerify, logoutVerify);
    this._options = samlConfig;
  }

  authenticate(req: Request, options: AuthenticateOptions): void {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }

      const mergedOptions = { ...this._options, ...samlOptions };
      const isIncomingMessage =
        !!(req.query?.SAMLResponse || req.query?.SAMLRequest || req.body?.SAMLResponse || req.body?.SAMLRequest);
      const isLoginStart = !isIncomingMessage && (options?.samlFallback ?? "login-request") === "login-request";
      if (isLoginStart && mergedOptions.validateInResponseTo === "always" && !mergedOptions.cacheProvider) {
        return this.error(
          new Error(
            'MultiSamlStrategy requires a shared cacheProvider when validateInResponseTo is "always". ' +
              "Each request creates a new SAML instance with its own cache. " +
              "For a single-process deployment, create an InMemoryCacheProvider once per identity provider " +
              "and return the same instance from getSamlOptions on every request.",
          ),
        );
      }

      const samlService = new SAML(mergedOptions);
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      super.authenticate.call(strategy, req, options);
    });
  }

  logout(
    req: RequestWithUser,
    callback: (err: Error | null, url?: string | null | undefined) => void,
  ): void {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const samlService = new SAML(Object.assign({}, this._options, samlOptions));
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      super.logout.call(strategy, req, callback);
    });
  }

  generateServiceProviderMetadata(
    req: Request,
    decryptionCert: string | null,
    signingCert: string | string[] | null,
    callback: (err: Error | null, metadata?: string) => void,
  ): void {
    if (typeof callback !== "function") {
      throw new Error("Metadata can't be provided synchronously for MultiSamlStrategy.");
    }

    return this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const samlService = new SAML(Object.assign({}, this._options, samlOptions));
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      return callback(
        null,
        this._generateServiceProviderMetadata.call(strategy, decryptionCert, signingCert),
      );
    });
  }

  // This is reduntant, but helps with testing
  error(err: Error): void {
    super.error(err);
  }
}
