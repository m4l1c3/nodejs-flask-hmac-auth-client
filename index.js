'use strict';

const crypto = require('crypto');

class FlaskHMACClient {
    constructor() {
        
    }

    compute(route, apikey, payload) {
        this.apikey = apikey;
        this.route = route;
        this.payload = payload;
        this.generateNonce(16);
        this.generateEpoch();
        let message = this.generateMessage();
        let hmac = this.buildHmac(message);
        return this.generateAuthcode(hmac);
    }

    buildHmac(message) {
        return crypto.createHmac('sha256', this.apikey).update(message).digest('hex');
    }

    generateMD5() {
        return crypto.createHash('md5').update(JSON.stringify(this.payload)).digest('hex');
    }

    generateNonce(length) {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for(var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        this.nonce = text;
    }

    generateEpoch() {
        this.epoch = Math.floor(new Date() / 1000);
    }

    generateMessage() {
        return '{}{}{}{}'.format(this.route, this.epoch, this.nonce, this.generateMD5());
    }

    generateAuthcode(hmac) {
        return '{}:{}:{}'.format(hmac, this.nonce, this.epoch);
    }
}

module.exports = new FlaskHMACClient();