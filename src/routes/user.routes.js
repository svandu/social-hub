import { Router } from "express";
import { logOutUser, loginUser, registerUser, getAllUser, refreshAccessToken } from "../controllers/user.controllers.js";
import {upload} from "../middlewares/multer.middleware.js" 
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router()

//middleware added in between the routes for the cover image and the avatar

router.get("/getuser", getAllUser)
router.route("/register").post(
    upload.fields([
        {
            name: "avatar", // name of the file 
            maxCount: 1 // number of the files count 
        },
        {
            name: "coverImage", // name of the file 
            maxCount: 1 // number of the files count 
        }
    ]),
    registerUser
)

router.route("/login").post(loginUser)

//secured routes 
router.route("/logout").post(verifyJWT, logOutUser) // verify by JWT as a middleware
router.route("/refresh-token").post(refreshAccessToken)

export default router