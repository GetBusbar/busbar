// Credential transport only. AccessControl's upstream assertions remain untouched.
var HttpSender = Java.type('org.parosproxy.paros.network.HttpSender');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var URI = Java.type('java.net.URI');
var UTF8 = Java.type('java.nio.charset.StandardCharsets').UTF_8;

function exchange(msg, phase) {
    var target = String(ScriptVars.getGlobalVar('busbar.callback'));
    var user = msg.getRequestingUser();
    if (user === null) throw new Error('AccessControl request has no named principal');
    var query = '?phase=' + phase + '&user=' + encodeURIComponent(String(user.getName())) +
        '&method=' + encodeURIComponent(String(msg.getRequestHeader().getMethod())) +
        '&uri=' + encodeURIComponent(String(msg.getRequestHeader().getURI().toString()));
    if (phase === 'response') query += '&status=' + msg.getResponseHeader().getStatusCode();
    var conn = URI.create(target + query).toURL().openConnection();
    conn.setConnectTimeout(5000);
    conn.setReadTimeout(5000);
    try {
        var input = conn.getInputStream();
        try { return JSON.parse(String(new (Java.type('java.lang.String'))(input.readAllBytes(), UTF8))); }
        finally { input.close(); }
    } finally { conn.disconnect(); }
}

function sendingRequest(msg, initiator, helper) {
    if (initiator !== HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR) return;
    try {
        // Never inherit a seed/previous identity's credential or session.
        msg.getRequestHeader().setHeader('Authorization', null);
        msg.getRequestHeader().setHeader('Cookie', null);
        var data = exchange(msg, 'request');
        if (data.authorization !== null) {
            msg.getRequestHeader().setHeader('Authorization', data.authorization);
        }
    } catch (error) {
        ScriptVars.setGlobalVar('busbar.transport.error', String(error));
        throw error;
    }
}

function responseReceived(msg, initiator, helper) {
    if (initiator !== HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR) return;
    try { exchange(msg, 'response'); }
    catch (error) {
        ScriptVars.setGlobalVar('busbar.transport.error', String(error));
        throw error;
    }
}
