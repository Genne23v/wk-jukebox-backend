const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { ExtractJwt, Strategy } = require('passport-jwt');
const dotenv = require('dotenv');

const app = express();
dotenv.config();
const HTTP_PORT = process.env.PORT || 8080;

const userService = require('./user-service.js');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors());

app.use(passport.initialize());
passport.use(
    new Strategy({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET,
        },
        async function verify(payload, done) {
            if (!payload) {
                return done(null, false);
            }

            const user = await userService.getUserById(payload.sub);
            if (!user) {
                return done(null, false);
            }
            done(null, user);
        }
    )
);

app.post('/api/user/register', async(req, res) => {
    const { userName, password, password2 } = req.body;

    if (!(userName && password && password2)) {
        return res.status(400).json({
            message: 'missing required user information',
        });
    }

    try {
        await userService.registerUser(req.body);
        res.status(201).json({
            message: `created user ${userName}`,
        });
    } catch (err) {
        res.status(422).json({
            message: err,
        });
    }
});

function createToken(user) {
    const { id, userName } = user;
    const payload = { sub: id, name: userName };
    const secret = process.env.JWT_SECRET;
    const options = { expiresIn: process.env.JWT_EXPIRE_IN || '2d' };
    return jwt.sign(payload, secret, options);
}

app.post('/api/user/login', async(req, res) => {
    const { userName, password } = req.body;
    if (!(userName && password)) {
        return res.status(400).json({
            message: 'missing required login information',
        });
    }

    try {
        const user = await userService.checkUser(req.body);

        if (user) {
            return res.json({
                message: 'login successful',
                token: createToken(user),
            });
        }
    } catch (err) {
        res.status(422).json({
            message: err,
        });
    }
});

app.get(
    '/api/user/favourites',
    passport.authenticate('jwt', { session: false }),
    async(req, res) => {
        try {
            const favourites = await userService.getFavourites(req.user._id);
            return res.status(200).json(favourites);
        } catch (err) {
            return res.status(400).json({
                message: `unable to fetch favourites list - ${err}`,
            });
        }
    }
);

app.put(
    '/api/user/favourites/:id',
    passport.authenticate('jwt', { session: false }),
    async(req, res) => {
        try {
            const favourites = await userService.addFavourite(
                req.user._id,
                req.params.id
            );
            return res.status(200).json(favourites);
        } catch (err) {
            return res.status(400).json({
                message: `unable to update favourite list`,
            });
        }
    }
);

app.delete(
    '/api/user/favourites/:id',
    passport.authenticate('jwt', { session: false }),
    async(req, res) => {
        try {
            const favourites = await userService.removeFavourite(
                req.user._id,
                req.params.id
            );
            return res.status(200).json(favourites);
        } catch (err) {
            return res.status(400).json({
                message: `unable to remove favourite list`
            })
        }
    }
);

userService
    .connect()
    .then(() => {
        app.listen(HTTP_PORT, () => {
            console.log('API listening on: ' + HTTP_PORT);
        });
    })
    .catch((err) => {
        console.log('unable to start the server: ' + err);
        process.exit();
    });