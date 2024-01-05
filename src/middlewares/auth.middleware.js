import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asyncHandler(async (req, _, next) => {
  try {
    //check the accesstoken if it available then it come in the format "Bearer<space>accessToken"
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer", ""); //we replace the bearer with the blank to get the accesstoken

    //if there is not accesstoken then we throw error
    if (!token) {
      throw new ApiError(401, "Unauthorized request");
    }

    // we verify the access token to the jwt toke i.e. we decode the token to check whether the token match with the jwt token or not
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    //now we find the user by its if to check that the user find or not
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    // if user is not available then we through the error
    if (!user) {
      throw new ApiError(401, "Invalid Access token");
    }

    // assign the user with the req user and then throw the next
    // add on new user 
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid access token");
  }
});
