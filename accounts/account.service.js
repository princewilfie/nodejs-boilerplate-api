const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sequelize = require('sequelize');
const { Op } = require('sequelize');
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');



module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};


async function authenticate({ email, password, ipAddress}){
    const account = await db.Account.scope('withHash').findOne({where: {email}});

    if(!account || !account.isVerified || !(await bcrypt.compare(password, account.passwordHash))) {
        throw 'Email or password is incorrect';

    }

    const jwtToken = generateJwtToken(account);
    const refreshToken = generatefreshToken(account, ipAddress);

    await refreshToken.save();

    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress}) {
    const refreshToken = await getRefreshToken(token);
    const account = await refreshToken.getAccount();


    const newRefreshToken = generateRefreshToken(account, ipAddress );
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();


    const jwtToken = generateJwtToken(account);

    return {
        ...basicDetails(account),
        refreshToken: newRefreshToken.token
    };
}


async function revokeToken({ token, ipAddress}){
    const refreshToken = await getRefreshToken(token);


    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}

async function register(params, origin){
    if (await db.Account.findOne({where: { email: params.email}})) {
        return await sendAlreadyRegisteredEmail(params.email, origin);
    
    }

    const account = new db.Account(params);

    const isFirstAccount = (await db.Account.count()) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.verificationToken = randomTokenString();

    account.passwordHash = await hash(params.password);


    await account.save();

    await sendVerificationEmail(account, origin);

}

async function verifyEmail({ token }) {
    const account = await db.Account.findOne({ where: {verificationToken: token}});

    if (!account) throw 'Verification failed';

    account.verified = Date.now();
    account.verificationToken = null;
    await account.save();
}

async function forgotPassword({email}, origin){
    const account = await db.Account.findOne({where: {email}});

    if (!account) return;

    account.resetToken = randomTokenString();
    account.resetTokenExpires = new Date(Date.now() + 24*60*60*1000);
    await account.save();

    await sendPasswordResetEmail(account, origin);

}

async function validateResetToken({ token }){
    const account = await db.Account.findOne({
        where: {
            resetToken: token,
            resetTokenExpires: {[Op.gt]: Date.now()}
        }
    });

    if(!account) throw 'Invalid token';

    return account;
}

async function resetPassword({ token, password}) {
    const account = await validateResetToken({ token });

    account.passwordHash = await hash(password);
    account.passwordReset = Date.now();
    account.resetToken = null;
    await account.save();

}

async function getAll() {
    const accounts = await db.Account.findAll();
    return accounts.map(x => basicDetails(x));
}

async function getById(id){
    const account = await getAccount (id);
    return basicDetails(account);
}

async function create(params) {

    if(await db.Account.findOne({where: {email: params.email}})){
        throw 'Email "' + params.email + '"is already registed';
    }

    const account = new db.Account(params);
    account.verified = Date.now();

    account.passwordHash = await hash(params.password);

    await account.save();

    return basicDetails(account);
}

async function update(id, params) {
    const account = await getAccount (id);

    if(params.email && account.email !== params.email && await db.Account.findOne({where: {email: params.email}})){
        throw 'Email "' + params.email + '" is already taken';

    }

    if(params.password) {
        params.passwordHash = await hash(params.password);

    }

    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();

    return basicDetails(account);
}
