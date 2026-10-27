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
import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";

// `MultiSamlStrategy` builds a new `SAML` instance for each request, and an instance with no
// `cacheProvider` starts with an empty one of its own, so nothing one request records is there for
// the next. Report the settings that can never work that way, at the first request they affect.
function missingSharedCacheError(
  req: Request,
  options: AuthenticateOptions,
  samlOptions: Partial<PassportSamlConfig>,
): Error | undefined {
  if (samlOptions.cacheProvider != null) {
    return undefined;
  }

  const isIncomingMessage = Boolean(
    req.query?.SAMLResponse ||
    req.query?.SAMLRequest ||
    req.body?.SAMLResponse ||
    req.body?.SAMLRequest,
  );
  const isLoginStart =
    !isIncomingMessage && (options.samlFallback ?? "login-request") === "login-request";

  let setting: string;
  if (isLoginStart && samlOptions.validateInResponseTo === ValidateInResponseTo.always) {
    // The callback could never find the request ID recorded here.
    setting = 'validateInResponseTo: "always"';
  } else if ((isLoginStart || req.body?.SAMLResponse) && samlOptions.rejectReplayedAssertions) {
    // An assertion presented again could never be found among those already accepted, and a
    // replayed one arrives at the callback, so a check only at login start would not stop it.
    setting = "rejectReplayedAssertions: true";
  } else {
    return undefined;
  }

  return new Error(
    `MultiSamlStrategy needs a cacheProvider shared across requests for ${setting}. ` +
      "It builds a new SAML instance for each request, and one without a cacheProvider starts " +
      "with an empty cache. Return the same cacheProvider for an identity provider from " +
      "getSamlOptions on every call; within one process, that can be one InMemoryCacheProvider " +
      "from @node-saml/node-saml for each identity provider.",
  );
}

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

      const cacheError = missingSharedCacheError(req, options, {
        ...this._options,
        ...samlOptions,
      });
      if (cacheError != null) {
        return this.error(cacheError);
      }

      const samlService = new SAML({ ...this._options, ...samlOptions });
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
