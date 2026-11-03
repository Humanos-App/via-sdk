import { parse } from "@marcbachmann/cel-js";
import type { ASTNode } from "@marcbachmann/cel-js";

/**
 * Route timestamp calls through the VIA string-or-number contract. Only parsed call names
 * change: quoted text, map keys, nested expressions and short-circuit guards keep their meaning.
 * Shared with the platform authoring checker so it checks the expression the verifier runs.
 */
export function rewriteCelTimestamps(expression: string): string {
  const positions: number[] = [];
  const visit = (node: ASTNode): void => {
    if (node.op === "call" && node.args[0] === "timestamp") positions.push(node.start);
    if (node.op === "value" || node.op === "id") return;
    const visitArgs = (value: unknown): void => {
      if (Array.isArray(value)) value.forEach(visitArgs);
      else if (value && typeof value === "object" && "op" in value) visit(value as ASTNode);
    };
    visitArgs(node.args);
  };
  visit(parse(expression).ast);
  let rewritten = expression;
  for (const start of positions.sort((a, b) => b - a)) {
    rewritten = rewritten.slice(0, start) + "viaTimestamp" + rewritten.slice(start + "timestamp".length);
  }
  return rewritten;
}
