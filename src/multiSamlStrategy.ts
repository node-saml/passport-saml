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

      // `getSamlOptions` may call back from a callback of its own, where a throw would escape
      // passport and crash the process, so an invalid configuration is reported instead.
      let samlService: SAML;
      try {
        samlService = new SAML({ ...this._options, ...samlOptions });
      } catch (error) {
        return this.error(error as Error);
      }
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

      let samlService: SAML;
      try {
        samlService = new SAML(Object.assign({}, this._options, samlOptions));
      } catch (error) {
        return callback(error as Error);
      }
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

      // The callback is called outside the `try`, so a throw from it is not reported to it again.
      let metadata: string;
      try {
        const samlService = new SAML(Object.assign({}, this._options, samlOptions));
        const strategy = Object.assign({}, this, { _saml: samlService });
        Object.setPrototypeOf(strategy, this);
        metadata = this._generateServiceProviderMetadata.call(
          strategy,
          decryptionCert,
          signingCert,
        );
      } catch (error) {
        return callback(error as Error);
      }
      return callback(null, metadata);
    });
  }

  // This is reduntant, but helps with testing
  error(err: Error): void {
    super.error(err);
  }
}
