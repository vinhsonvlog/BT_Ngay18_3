let express = require('express');
let router = express.Router()
let fs = require('fs');
let path = require('path');
let userController = require('../controllers/users')
let bcrypt = require('bcrypt');
const { CheckLogin } = require('../utils/authHandler');
const { ChangePasswordValidator, validatedResult } = require('../utils/validator');
let jwt = require('jsonwebtoken')
const privateKey = fs.readFileSync(path.join(__dirname, '..', 'private.pem'));
router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b116d4ae6f6cf7d4021eb3"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
            return;
        }
        if (user.lockTime > Date.now()) {
            res.status(404).send({
                message: "ban dang bi ban"
            })
            return;
        }
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            //let priK = fs.readFileSync('privateKey.pem')
            let token = jwt.sign({
                id: user._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1d'
            })
            res.send(token)
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }
            await user.save()
            res.status(404).send({
                message: "thong tin dang nhap khong dung"
            })
        }
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})
router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user)
})
router.put('/changepassword', CheckLogin, ChangePasswordValidator, validatedResult, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        if (!bcrypt.compareSync(oldpassword, req.user.password)) {
            res.status(404).send({
                message: "mat khau cu khong dung"
            })
            return;
        }

        req.user.password = newpassword;
        await req.user.save();

        res.send({
            message: "doi mat khau thanh cong"
        })
    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})
module.exports = router