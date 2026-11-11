// ZAP 2.17.0 only calls these lifecycle hooks through View.discardContexts().
// Its headless newSession discards the database/tree but leaves extension maps.
// Perform the same public reset for every loaded factory before newSession;
// no request, credential, access rule or report is reused between operations.
var Control = Java.type('org.parosproxy.paros.control.Control');
var Factory = Java.type('org.zaproxy.zap.view.ContextPanelFactory');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var loader = Control.getSingleton().getExtensionLoader();
var factories = [];
for (var i = 0; i < loader.getExtensionCount(); i++) {
    var extension = loader.getExtension(i);
    if (extension instanceof Factory) {
        extension.discardContexts();
        factories.push(String(extension.getClass().getName()));
    }
}
ScriptVars.setGlobalVar('busbar.reset.ready', JSON.stringify({factories: factories}));
