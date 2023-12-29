import { Router } from "express";
import { registerUser } from "../controllers/user.controllers.js";
import {upload} from "../middlewares/multer.middleware.js" 

const router = Router()

//middleware added in between the routes for the cover image and the avatar
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

export default router