import { createHash, verify } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(process.argv[2] ?? process.cwd());
const lockPath = "policy/desired-state-lock.json";
const contentLockPath = "infra/flux/targets/testnet/stages/gate/content-lock.yaml";
const requiredPayload = new Set([
  ".github/workflows/validate.yml",
  "infra/flux/targets/testnet/control-plane/reconciliation.yaml",
  "infra/flux/targets/testnet/control-plane/source.yaml",
  "infra/flux/targets/testnet/materialization.json",
  "infra/flux/targets/testnet/stages/gate/clawrelease.json",
  "scripts/check-desired-state.mjs",
  "trust/deployment-intent-public-key.pem",
]);
const permittedPath = /^(?:\.github\/workflows\/validate\.yml|infra\/flux\/targets\/testnet\/.+|infra\/k8s\/base\/.+|policy\/desired-state-lock\.json|scripts\/check-desired-state\.mjs|trust\/deployment-intent-public-key\.pem)$/u;
const digestPattern = /^sha256:[a-f0-9]{64}$/u;

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("canonical_json_number_invalid");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  throw new Error("canonical_json_value_invalid");
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function namedFilesDigest(files) {
  const hash = createHash("sha256");
  for (const file of [...files].sort((left, right) => left.name.localeCompare(right.name, "en"))) {
    hash.update(file.name, "utf8");
    hash.update("\0");
    hash.update(file.bytes);
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

function walk(directory, prefix = "") {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (prefix === "" && entry.name === ".git") continue;
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolute = path.join(directory, entry.name);
    const metadata = lstatSync(absolute);
    if (metadata.isSymbolicLink()) throw new Error(`symlink_forbidden:${relative}`);
    if (metadata.isDirectory()) files.push(...walk(absolute, relative));
    else if (metadata.isFile()) files.push(relative);
    else throw new Error(`special_file_forbidden:${relative}`);
  }
  return files;
}

function readCanonicalJson(relative) {
  const raw = readFileSync(path.join(root, relative));
  let value;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error(`json_invalid:${relative}`);
  }
  if (!raw.equals(Buffer.from(`${canonicalJson(value)}\n`))) {
    throw new Error(`json_not_canonical:${relative}`);
  }
  return value;
}

function exactKeys(value, keys, label) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())
  ) {
    throw new Error(`${label}_shape_invalid`);
  }
}

function count(raw, expression) {
  return raw.match(expression)?.length ?? 0;
}

function validate() {
  const files = walk(root).sort();
  const unpermitted = files.find((file) => !permittedPath.test(file));
  if (unpermitted) throw new Error(`path_not_allowlisted:${unpermitted}`);
  const lock = readCanonicalJson(lockPath);
  exactKeys(lock, [
    "schemaVersion", "activation", "environment", "intentDigest", "intentKeyId",
    "intentPublicKeyDigest", "releaseId", "gitSha", "releasePackage", "sourceUrl",
    "readyReference", "readyArtifactDigest", "readyReleaseAttestationDigest",
    "readyPolicyRevision", "readyPolicyDigest", "admission", "contentDigest", "files",
  ], "desired_state_lock");
  if (
    lock.schemaVersion !== 1 || !["shadow", "active"].includes(lock.activation) ||
    lock.environment !== "testnet" || !digestPattern.test(lock.intentDigest) ||
    !digestPattern.test(lock.intentPublicKeyDigest) || !digestPattern.test(lock.contentDigest) ||
    !/^[a-z0-9][a-z0-9-]{0,50}$/u.test(lock.releaseId) ||
    !/^[a-f0-9]{40}$/u.test(lock.gitSha) ||
    !/^[A-Za-z0-9._:-]{1,128}$/u.test(lock.intentKeyId) ||
    !/^[a-z0-9][a-z0-9._:-]*(?:\/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$/u.test(lock.releasePackage) ||
    !/^[a-z0-9][a-z0-9._:-]*(?:\/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$/u.test(lock.readyReference) ||
    !digestPattern.test(lock.readyArtifactDigest) ||
    !digestPattern.test(lock.readyReleaseAttestationDigest) ||
    !digestPattern.test(lock.readyPolicyDigest) ||
    !Number.isSafeInteger(lock.readyPolicyRevision) || lock.readyPolicyRevision < 1 ||
    !lock.readyReference.endsWith(`@${lock.readyArtifactDigest}`)
  ) {
    throw new Error("desired_state_lock_identity_invalid");
  }
  const sourceUrl = new URL(lock.sourceUrl);
  if (
    sourceUrl.protocol !== "https:" || sourceUrl.username || sourceUrl.password ||
    sourceUrl.search || sourceUrl.hash || sourceUrl.port
  ) {
    throw new Error("desired_state_source_url_invalid");
  }
  if (lock.files === null || typeof lock.files !== "object" || Array.isArray(lock.files)) {
    throw new Error("desired_state_lock_files_shape_invalid");
  }
  const payloadPaths = Object.keys(lock.files).sort();
  if (
    payloadPaths.some((file) => !permittedPath.test(file) || file === lockPath) ||
    [...requiredPayload].some((file) => !payloadPaths.includes(file)) ||
    JSON.stringify(files) !== JSON.stringify([...payloadPaths, lockPath, contentLockPath].sort())
  ) {
    throw new Error("desired_state_file_set_invalid");
  }
  const payload = payloadPaths.map((name) => {
    const bytes = readFileSync(path.join(root, name));
    if (lock.files[name] !== sha256(bytes)) throw new Error(`file_digest_mismatch:${name}`);
    return { name, bytes };
  });
  if (namedFilesDigest(payload) !== lock.contentDigest) {
    throw new Error("desired_state_content_digest_mismatch");
  }
  const contentLock = readFileSync(path.join(root, contentLockPath), "utf8");
  const expectedContentLock = [
    "apiVersion: v1",
    "kind: ConfigMap",
    "metadata:",
    "  name: claw-desired-state-content-lock",
    "  namespace: claw-testnet",
    "data:",
    `  contentDigest: ${lock.contentDigest}`,
    `  intentDigest: ${lock.intentDigest}`,
    `  releaseSha: "${lock.gitSha}"`,
    "",
  ].join("\n");
  if (contentLock !== expectedContentLock) {
    throw new Error("desired_state_content_lock_invalid");
  }

  const publicKey = readFileSync(path.join(root, "trust/deployment-intent-public-key.pem"));
  if (sha256(publicKey) !== lock.intentPublicKeyDigest) {
    throw new Error("intent_public_key_digest_mismatch");
  }
  const clawRelease = readCanonicalJson(
    "infra/flux/targets/testnet/stages/gate/clawrelease.json",
  );
  exactKeys(clawRelease, ["apiVersion", "kind", "metadata", "spec"], "clawrelease");
  const intent = clawRelease.spec?.intent;
  const signature = clawRelease.spec?.signature;
  const intentDigest = sha256(Buffer.from(canonicalJson(intent)));
  if (
    clawRelease.apiVersion !== "delivery.claw.io/v1alpha2" ||
    clawRelease.kind !== "ClawRelease" || clawRelease.metadata?.namespace !== "claw-testnet" ||
    clawRelease.status !== undefined || clawRelease.spec?.intentDigest !== intentDigest ||
    intentDigest !== lock.intentDigest || signature?.algorithm !== "ed25519" ||
    signature?.keyId !== lock.intentKeyId || signature?.manifestDigest !== intentDigest ||
    !verify(
      null,
      Buffer.from(canonicalJson(intent)),
      publicKey,
      Buffer.from(String(signature?.signature ?? ""), "base64"),
    )
  ) {
    throw new Error("clawrelease_signature_or_digest_invalid");
  }
  if (
    intent?.environment !== "testnet" || intent?.target?.namespace !== "claw-testnet" ||
    intent?.target?.identity?.environment !== "testnet" || intent?.target?.identity?.chainId !== 97 ||
    intent?.target?.signer !== "disabled" || intent?.release?.config?.schemaVersion !== 1 ||
    !/^sha256:[a-f0-9]{64}$/u.test(String(intent?.release?.config?.bundleDigest ?? "")) ||
    !Number.isSafeInteger(intent?.release?.config?.revision) || intent.release.config.revision < 1 ||
    intent?.release?.releaseId !== lock.releaseId || intent?.release?.gitSha !== lock.gitSha ||
    intent?.release?.releasePackage?.reference !== lock.releasePackage ||
    intent?.release?.ready?.readyReference !== lock.readyReference ||
    intent?.release?.ready?.readyArtifactDigest !== lock.readyArtifactDigest ||
    intent?.release?.ready?.readyReleaseAttestationDigest !== lock.readyReleaseAttestationDigest ||
    intent?.release?.ready?.policyRevision !== lock.readyPolicyRevision ||
    intent?.release?.ready?.policyDigest !== lock.readyPolicyDigest ||
    canonicalJson(intent?.admission) !== canonicalJson(lock.admission) ||
    intent?.flux?.sourceUrl !== lock.sourceUrl || intent?.flux?.sourceAuthentication !== "anonymous-public" ||
    intent?.flux?.commitVerification !== "HEAD" || intent?.flux?.sourceNamespace !== "claw-flux-testnet" ||
    intent?.flux?.path !== "./infra/flux/targets/testnet" || intent?.flux?.crossNamespaceRefs !== false ||
    intent?.flux?.remoteBases !== false || intent?.flux?.imageAutomation !== false ||
    intent?.safety?.destructiveCutover !== "forbidden"
  ) {
    throw new Error("testnet_intent_boundary_invalid");
  }
  for (const name of ["backend", "web", "admin"]) {
    const image = intent?.release?.images?.[name];
    if (
      image?.platform !== "linux/amd64" ||
      !new RegExp(`^127\\.0\\.0\\.1:5000/claw/${name}@sha256:[a-f0-9]{64}$`, "u")
        .test(String(image?.cachedReference ?? "")) ||
      !/^[a-z0-9][a-z0-9._:-]*(?:\/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$/u
        .test(String(image?.reference ?? ""))
    ) {
      throw new Error(`immutable_image_binding_invalid:${name}`);
    }
  }

  const source = readFileSync(path.join(
    root,
    "infra/flux/targets/testnet/control-plane/source.yaml",
  ), "utf8");
  const reconciliation = readFileSync(path.join(
    root,
    "infra/flux/targets/testnet/control-plane/reconciliation.yaml",
  ), "utf8");
  if (
    count(source, /^kind: GitRepository$/gmu) !== 1 ||
    count(source, /^  suspend: false$/gmu) !== 1 ||
    count(source, /^    mode: HEAD$/gmu) !== 1 || !source.includes(`  url: ${lock.sourceUrl}`) ||
    count(reconciliation, /^kind: Kustomization$/gmu) !== 5 ||
    count(reconciliation, /^  suspend: true$/gmu) !== (lock.activation === "shadow" ? 5 : 0) ||
    count(reconciliation, /^  suspend: false$/gmu) !== (lock.activation === "active" ? 5 : 0)
  ) {
    throw new Error("flux_source_or_suspension_invalid");
  }
  const materialization = readCanonicalJson("infra/flux/targets/testnet/materialization.json");
  if (
    materialization.activation !== lock.activation || materialization.environment !== "testnet" ||
    materialization.intentDigest !== lock.intentDigest || materialization.releaseId !== lock.releaseId ||
    materialization.gitSha !== lock.gitSha || materialization.releasePackage !== lock.releasePackage ||
    materialization.readyReference !== lock.readyReference ||
    materialization.readyArtifactDigest !== lock.readyArtifactDigest ||
    materialization.readyReleaseAttestationDigest !== lock.readyReleaseAttestationDigest ||
    materialization.readyPolicyRevision !== lock.readyPolicyRevision ||
    materialization.readyPolicyDigest !== lock.readyPolicyDigest ||
    canonicalJson(materialization.admission) !== canonicalJson(lock.admission) ||
    materialization.gitUrl !== lock.sourceUrl ||
    (lock.activation === "shadow" && materialization.shadowEvidenceDigest !== null) ||
    (lock.activation === "active" && !digestPattern.test(materialization.shadowEvidenceDigest))
  ) {
    throw new Error("materialization_binding_invalid");
  }

  const allText = payload.map(({ bytes }) => bytes.toString("utf8")).join("\n");
  const deploymentText = payload
    .filter(({ name }) => name.startsWith("infra/"))
    .map(({ bytes }) => bytes.toString("utf8"))
    .join("\n");
  if (/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/u.test(allText)) {
    throw new Error("private_key_forbidden");
  }
  for (const [code, expression] of [
    ["secret_resource_forbidden", /^kind:\s*(?:Secret|OCIRepository|ImageUpdateAutomation|ImagePolicy|ImageRepository)\s*$/gmu],
    ["mainnet_forbidden", /(?:BSC\s+Mainnet|"chainId":56|"environment":"production"|environment:\s*production)/iu],
    ["signer_enabled_forbidden", /"signer":"(?!disabled")[^"]+"/u],
    ["floating_latest_forbidden", /\bimage:\s*[^\s]+:latest\b/iu],
  ]) {
    if (expression.test(deploymentText)) throw new Error(code);
  }
  if (files.some((file) => /(?:^|\/)(?:\.env(?:\.|$)|credentials?|private[-_.]?key)/iu.test(file))) {
    throw new Error("sensitive_filename_forbidden");
  }
  process.stdout.write(`${canonicalJson({
    schemaVersion: 1,
    action: "desired-state.verify",
    activation: lock.activation,
    environment: lock.environment,
    gitSha: lock.gitSha,
    intentDigest: lock.intentDigest,
    contentDigest: lock.contentDigest,
    files: payload.length,
  })}\n`);
}

try {
  validate();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "desired_state_invalid"}\n`);
  process.exitCode = 1;
}
