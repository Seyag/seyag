export type Proposal = { kind: string; target: string; reason: string };
export type RelayAction = { type: string; args: Record<string, unknown> };
export interface ToolContext { getSummary(): Promise<unknown>; enqueueProposal(proposal: Proposal): Promise<string>; enqueueAction(action: RelayAction): Promise<string> }
type Tool = { definition: Record<string, unknown>; call(args: Record<string, unknown>, context: ToolContext): Promise<unknown> };
const kinds = ["domain", "channel", "app", "window", "appeal"] as const;
const canonicalTarget: Record<string, RegExp> = {
  domain: /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/,
  channel: /^(?:UC[A-Za-z0-9_-]{22}|@[A-Za-z0-9._-]{3,30})$/,
  app: /^(?:[A-Za-z][A-Za-z0-9_-]*)(?:\.[A-Za-z0-9_-]+)+$/,
  window: /^(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]$/,
  appeal: /^[A-Za-z0-9_-]{1,64}$/,
};
const reason = (value: unknown) => typeof value === "string" && value.trim().length > 0 && value.trim().length <= 500;
const target = (kind: "domain"|"channel"|"app", value: unknown) => typeof value === "string" && value.length <= 200 && canonicalTarget[kind].test(value) && (kind !== "domain" || value === value.toLowerCase());
export function validProposal(value: Record<string, unknown>): value is Proposal {
  const kind = typeof value.kind === "string" ? value.kind : "", valueTarget = value.target;
  return kinds.includes(kind as typeof kinds[number]) && typeof valueTarget === "string" && valueTarget.length <= 200
    && reason(value.reason) && canonicalTarget[kind].test(valueTarget)
    && (kind !== "domain" || valueTarget === valueTarget.toLowerCase());
}
const objectSchema = (properties:Record<string,unknown>, required:string[]) => ({type:"object",properties,required,additionalProperties:false});
const queued = (id:string, status="queued_for_home") => ({content:[{type:"text",text:JSON.stringify({id,status})}]});
const registry: Record<string, Tool> = {
  read_summary: {
    definition: { name: "read_summary", description: "Read the capped committee rules, active mode, appeals, blocked-domain counts, approved YouTube channels, app verdicts, and recent committee requests. When the owner asks about a request, tell him the committee decision, the decision note for each request and its earliest date.", inputSchema: objectSchema({},[]) },
    async call(_args, context) { return { content: [{ type: "text", text: JSON.stringify(await context.getSummary()) }] }; },
  },
  propose: {
    definition: { name: "propose", description: "Submit a structured proposal for owner review. This is the only loosening path and never changes policy directly. App targets are iOS bundle IDs, never Android package names.", inputSchema: objectSchema({kind:{type:"string",enum:kinds},target:{type:"string",minLength:1,maxLength:200},reason:{type:"string",minLength:1,maxLength:500}},["kind","target","reason"]) },
    async call(args, context) { if (!validProposal(args) || !reason(args.reason)) throw new TypeError("Invalid proposal"); return queued(await context.enqueueProposal({kind:String(args.kind),target:String(args.target),reason:String(args.reason).trim()}), "proposed"); },
  },
};
for (const [name,kind] of [["block_domain","domain"],["block_app","app"],["block_channel","channel"]] as const) registry[name]={
  definition:{name,description:`Queue an immediate tightening action to block a ${kind} at home.`,inputSchema:objectSchema({target:{type:"string",minLength:1,maxLength:200},reason:{type:"string",minLength:1,maxLength:500}},["target","reason"])},
  async call(args,context){if(!target(kind,args.target)||!reason(args.reason))throw new TypeError("Invalid action");return queued(await context.enqueueAction({type:name,args:{target:args.target,reason:String(args.reason).trim()}}));}
};
registry.start_focus={definition:{name:"start_focus",description:"Queue a 15-240 minute focus block using a configured topic.",inputSchema:objectSchema({topic:{type:"string",minLength:1,maxLength:200},duration:{type:"integer",minimum:15,maximum:240}},["topic","duration"])},async call(args,context){if(typeof args.topic!=="string"||!args.topic||args.topic.length>200||!Number.isInteger(args.duration)||Number(args.duration)<15||Number(args.duration)>240)throw new TypeError("Invalid action");return queued(await context.enqueueAction({type:"start_focus",args:{topic:args.topic,duration:args.duration}}));}};
registry.close_install_window={definition:{name:"close_install_window",description:"Queue immediate closure of every device install window.",inputSchema:objectSchema({},[])},async call(args,context){if(Object.keys(args).length)throw new TypeError("Invalid action");return queued(await context.enqueueAction({type:"close_install_window",args:{}}));}};
registry.submit_appeal={definition:{name:"submit_appeal",description:"Queue a pending appeal for a host; this does not approve or loosen it.",inputSchema:objectSchema({host:{type:"string",minLength:1,maxLength:200},reason:{type:"string",minLength:1,maxLength:500}},["host","reason"])},async call(args,context){if(!target("domain",args.host)||!reason(args.reason))throw new TypeError("Invalid action");return queued(await context.enqueueAction({type:"submit_appeal",args:{host:args.host,reason:String(args.reason).trim()}}));}};
export const toolDefinitions = () => Object.values(registry).map(tool => tool.definition);
export async function callTool(name: string, args: Record<string, unknown>, context: ToolContext) { const tool=registry[name]; return tool ? tool.call(args,context) : undefined; }
