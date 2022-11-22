import { Strategy, AbstractStrategy } from "./strategy";
import { MultiSamlStrategy } from "./multiSamlStrategy";

import type {
  VerifiedCallback,
  VerifyWithRequest,
  VerifyWithoutRequest,
  MultiStrategyConfig,
} from "./types";

export * from "@node-saml/node-saml";

export {
  AbstractStrategy,
  Strategy,
  MultiSamlStrategy,
  VerifiedCallback,
  VerifyWithRequest,
  VerifyWithoutRequest,
  MultiStrategyConfig,
};
