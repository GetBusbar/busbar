// Configure inputs to the upstream judge. This script never grades a response.
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var Model = Java.type('org.parosproxy.paros.model.Model');
var Control = Java.type('org.parosproxy.paros.control.Control');
var Extension = Java.type('org.zaproxy.zap.extension.accessControl.ExtensionAccessControl');
var SiteTreeNode = Java.type('org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode');
var AccessRule = Java.type('org.zaproxy.zap.extension.accessControl.AccessRule');
var URI = Java.type('org.apache.commons.httpclient.URI');
var spec = JSON.parse(String(ScriptVars.getGlobalVar('busbar.operation')));
var uri = new URI(spec.uri, true);
// Reuse the actual recorded leaf. Reconstructing a leaf with findNode(uri,
// method, body) loses the JSON Content-Type and can derive a different parameter
// suffix, silently missing POST operations. The fresh session contains one seed.
var entries = Model.getSingleton().getSession().getSiteTree().getRoot().depthFirstEnumeration();
var matches = [];
while (entries.hasMoreElements()) {
    var candidate = entries.nextElement();
    if (!candidate.isLeaf() || candidate.getHistoryReference() === null) continue;
    var recorded = candidate.getHistoryReference().getHttpMessage();
    if (String(recorded.getRequestHeader().getMethod()) === spec.method &&
        String(recorded.getRequestHeader().getURI().toString()) === spec.uri &&
        String(recorded.getRequestBody().toString()) === spec.body &&
        !recorded.getResponseHeader().isEmpty()) {
        matches.push(candidate);
    }
}
if (matches.length !== 1) throw new Error('exact recorded operation leaf missing or ambiguous');
var node = matches[0];
var extension = Control.getSingleton().getExtensionLoader().getExtension(Extension.class);
var manager = extension.getContextAccessRulesManager(spec.context);
for (var user of spec.users) {
    var leaf = new SiteTreeNode(node.getNodeName(), uri);
    manager.addRule(user.id, leaf, AccessRule.valueOf(user.rule));
    if (String(manager.getDefinedRule(user.id, leaf).name()) !== user.rule) {
        throw new Error('explicit rule was not installed');
    }
}
ScriptVars.setGlobalVar('busbar.rules.ready', JSON.stringify({
    method: spec.method, uri: spec.uri, node: String(node.getNodeName()), cells: spec.users.length
}));
