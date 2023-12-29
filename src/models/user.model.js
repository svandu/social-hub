import mongoose, {Schema} from "mongoose";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true // this index is used for searching
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true // this index is used for searching
        },
        avatar: {
            type: String, //cloudinary url used 
            required: true
        },
        coverImage: {
            type: String, //cloudinary url used 
        },
        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video"
            }
        ],
        password: {
            type: String,
            required: [true, 'Password is required'],
        },
        refreshToken: {
            type: String
        },
    },
    {
        timestamps: true
    }
)

/**
 * Encrypt the password using pre keyword that is middleware that encrypt the password before it save of the specified schema 
 * next tell that the work is completed and move it forward 
 * async is used because it takes time to encrypt the password
 * 10 is the cost factor. The cost factor determines the number of iterations used in the hashing process
 */
userSchema.pre("save", async function(next) {
    if(!this.isModified('password')) return next() 
    this.password = await bcrypt.hash(this.password, 10)
    next()
})

//customize method to check the password is correct or not 
userSchema.methods.isPasswordCorrect = async function(password) {
    return await bcrypt.compare(password, this.password) // return value is true or false
}

userSchema.methods.generateAccessToken = function() {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

// we are doing same with refresh token as it has less information because it is refreshing again and again

userSchema.methods.generateRefreshToken = function() {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema)
