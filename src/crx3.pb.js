// CrxFileHeader ========================================

export var CrxFileHeader = {};

CrxFileHeader.read = function (pbf, end) {
    return pbf.readFields(CrxFileHeader._readField, {sha256_with_rsa: [], sha256_with_ecdsa: [], signed_header_data: null}, end);
};
CrxFileHeader._readField = function (tag, obj, pbf) {
    if (tag === 2) obj.sha256_with_rsa.push(AsymmetricKeyProof.read(pbf, pbf.readVarint() + pbf.pos));
    else if (tag === 3) obj.sha256_with_ecdsa.push(AsymmetricKeyProof.read(pbf, pbf.readVarint() + pbf.pos));
    else if (tag === 10000) obj.signed_header_data = pbf.readBytes();
};
CrxFileHeader.write = function (obj, pbf) {
    if (obj.sha256_with_rsa) for (var i = 0; i < obj.sha256_with_rsa.length; i++) pbf.writeMessage(2, AsymmetricKeyProof.write, obj.sha256_with_rsa[i]);
    if (obj.sha256_with_ecdsa) for (i = 0; i < obj.sha256_with_ecdsa.length; i++) pbf.writeMessage(3, AsymmetricKeyProof.write, obj.sha256_with_ecdsa[i]);
    if (obj.signed_header_data) pbf.writeBytesField(10000, obj.signed_header_data);
};

// AsymmetricKeyProof ========================================

export var AsymmetricKeyProof = {};

AsymmetricKeyProof.read = function (pbf, end) {
    return pbf.readFields(AsymmetricKeyProof._readField, {public_key: null, signature: null}, end);
};
AsymmetricKeyProof._readField = function (tag, obj, pbf) {
    if (tag === 1) obj.public_key = pbf.readBytes();
    else if (tag === 2) obj.signature = pbf.readBytes();
};
AsymmetricKeyProof.write = function (obj, pbf) {
    if (obj.public_key) pbf.writeBytesField(1, obj.public_key);
    if (obj.signature) pbf.writeBytesField(2, obj.signature);
};

// SignedData ========================================

export var SignedData = {};

SignedData.read = function (pbf, end) {
    return pbf.readFields(SignedData._readField, {crx_id: null}, end);
};
SignedData._readField = function (tag, obj, pbf) {
    if (tag === 1) obj.crx_id = pbf.readBytes();
};
SignedData.write = function (obj, pbf) {
    if (obj.crx_id) pbf.writeBytesField(1, obj.crx_id);
};