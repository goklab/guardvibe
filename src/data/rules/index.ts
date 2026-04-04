export type { SecurityRule } from "./types.js";
import { coreRules } from "./core.js";
import { goRules } from "./go.js";
import { dockerfileRules } from "./dockerfile.js";
import { cicdRules } from "./cicd.js";
import { terraformRules } from "./terraform.js";
import { nextjsRules } from "./nextjs.js";
import { authRules } from "./auth.js";
import { databaseRules } from "./database.js";
import { deploymentRules } from "./deployment.js";
import { paymentRules } from "./payments.js";
import { serviceRules } from "./services.js";
import { webSecurityRules } from "./web-security.js";
import { reactNativeRules } from "./react-native.js";
import { firebaseRules } from "./firebase.js";
import { otherServiceRules } from "./other-services.js";
import { shellRules } from "./shell.js";
import { sqlRules } from "./sql.js";
import { aiSecurityRules } from "./ai-security.js";
import { supplyChainRules } from "./supply-chain.js";
import { cveVersionRules } from "./cve-versions.js";
import { apiSecurityRules } from "./api-security.js";
import { modernStackRules } from "./modern-stack.js";
import { advancedSecurityRules } from "./advanced-security.js";
import { aiHostSecurityRules } from "./ai-host-security.js";
import { aiToolRuntimeRules } from "./ai-tool-runtime.js";
import { enrichRulesWithCompliance } from "../compliance-metadata.js";

export const owaspRules = enrichRulesWithCompliance([
  ...coreRules,
  ...goRules,
  ...dockerfileRules,
  ...cicdRules,
  ...terraformRules,
  ...nextjsRules,
  ...authRules,
  ...databaseRules,
  ...deploymentRules,
  ...paymentRules,
  ...serviceRules,
  ...webSecurityRules,
  ...reactNativeRules,
  ...firebaseRules,
  ...otherServiceRules,
  ...shellRules,
  ...sqlRules,
  ...aiSecurityRules,
  ...supplyChainRules,
  ...cveVersionRules,
  ...apiSecurityRules,
  ...modernStackRules,
  ...advancedSecurityRules,
  ...aiHostSecurityRules,
  ...aiToolRuntimeRules,
]);

// Alias for clarity — these are the built-in rules without plugins
export const builtinRules = owaspRules;
