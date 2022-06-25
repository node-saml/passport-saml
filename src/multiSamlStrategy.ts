import { AbstractStrategy } from "./strategy";
import type { Request } from "express";
import {
  AuthenticateOptions,
  MultiStrategyConfig,
  RequestWithUser,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";
import { SAML, SamlConfig } from "@node-saml/node-saml";

export class MultiSamlStrategy extends AbstractStrategy {
  static readonly newSamlProviderOnConstruct = false;
  _options: SamlConfig & MultiStrategyConfig;

  constructor(
    options: MultiStrategyConfig,
    signonVerify: VerifyWithRequest,
    logoutVerify: VerifyWithRequest
  );
  constructor(
    options: MultiStrategyConfig,
    signonVerify: VerifyWithoutRequest,
    logoutVerify: VerifyWithoutRequest
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
    } as SamlConfig & MultiStrategyConfig;

    super(samlConfig, signonVerify, logoutVerify);
    this._options = samlConfig;
  }

  authenticate(req: RequestWithUser, options: AuthenticateOptions): void {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }

      const samlService = new SAML({ ...this._options, ...samlOptions });
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      super.authenticate.call(strategy, req, options);
    });
  }

  logout(
    req: RequestWithUser,
    callback: (err: Error | null, url?: string | null | undefined) => void
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
    callback: (err: Error | null, metadata?: string) => void
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
        this._generateServiceProviderMetadata.call(strategy, decryptionCert, signingCert)
      );
    });
  }

  // This is reduntant, but helps with testing
  error(err: Error): void {
    super.error(err);
  }
}
