import * as util from "util";
import * as saml from "./saml";
import { CacheProvider as InMemoryCacheProvider } from "./inmemory-cache-provider";
import SamlStrategy = require("./strategy");
import type { Request } from "express";
import {
  AuthenticateOptions,
  AuthorizeOptions,
  MultiSamlConfig,
  RequestWithUser,
  SamlConfig,
  VerifyWithoutRequest,
  VerifyWithRequest,
} from "./types";

class MultiSamlStrategy extends SamlStrategy {
  _options: SamlConfig & MultiSamlConfig;

  constructor(options: MultiSamlConfig, verify: VerifyWithRequest);
  constructor(options: MultiSamlConfig, verify: VerifyWithoutRequest);
  constructor(options: MultiSamlConfig, verify: never) {
    if (!options || typeof options.getSamlOptions !== "function") {
      throw new Error("Please provide a getSamlOptions function");
    }

    const samlConfig: SamlConfig & MultiSamlConfig = {
      ...options,
      cert: options.cert ?? "fake cert", // This would never be a valid cert, to it serves to be a good placeholder
    };

    super(samlConfig, verify);
    this._options = samlConfig;
  }

  authenticate(req: RequestWithUser, options: AuthenticateOptions): void {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return this.error(err);
      }

      const samlService = new saml.SAML({ ...this._options, ...samlOptions });
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      super.authenticate.call(strategy, req, options);
    });
  }

  logout(
    req: RequestWithUser,
    callback: (err: Error | null, url?: string | null | undefined) => void
  ) {
    this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      super.logout.call(strategy, req, callback);
    });
  }

  /** @ts-expect-error typescript disallows changing method signature in a subclass */
  generateServiceProviderMetadata(
    req: Request,
    decryptionCert: string | null,
    signingCert: string | null,
    callback: (err: Error | null, metadata?: string) => void
  ) {
    if (typeof callback !== "function") {
      throw new Error("Metadata can't be provided synchronously for MultiSamlStrategy.");
    }

    return this._options.getSamlOptions(req, (err, samlOptions) => {
      if (err) {
        return callback(err);
      }

      const samlService = new saml.SAML(Object.assign({}, this._options, samlOptions));
      const strategy = Object.assign({}, this, { _saml: samlService });
      Object.setPrototypeOf(strategy, this);
      return callback(
        null,
        super.generateServiceProviderMetadata.call(strategy, decryptionCert, signingCert)
      );
    });
  }

  // This is reduntant, but helps with testing
  error(err: Error): void {
    super.error(err);
  }
}

export = MultiSamlStrategy;
