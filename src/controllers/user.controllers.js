import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessandRefreshTokens = async (userId) => {
  try {
    //check the user by its Id that it is available in mongoose or not by findById method and store in a variable
    const user = await User.findById(userId);

    // take the refresh and access token from user
    const refreshToken = await user.generateRefreshToken();
    const accessToken = await user.generateAccessToken();

    // store the user refresh token in a variable refreshToken
    user.refreshToken = refreshToken;

    // save the user in a database but apply the condition that not to validate before saving
    await user.save({ validateBeforeSave: false });

    //return the access and refresh token
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const getAllUser = asyncHandler(async (req, res) => {
  try {
    const user = await User.find({});

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error" });
  }
});

const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  // validation - not empty
  // check if user already exists: username, email
  // check for images, check for avatar
  // upload them to cloudinary, avatar
  // create user object - create entry in db
  // remove password and refresh token field from response
  // check for user creation
  // return response

  const { fullName, email, username, password } = req.body;
  // console.log("email", email);

  // check the validation that any field is empty or any other whitespace are not available
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // check that the user is already exist or not by taking username and the email
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exist");
  }

  console.log(req.files);

  //check for images and the avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;

  //check the condition if the coverImage is available then we add it in the request file
  //isArray is used to check that the coverImage is an array or not
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  //upload images to cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // create user object - create entry in db
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  ); //find the user

  // remove password and refresh token field from response
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong whole registering user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  /**
   * req body -> data
   * username or email check (available or not)
   * find the user in database
   * password check invalid or valid
   * access and refresh token
   * send cookie
   */

  //take username, email and password from the req body
  const { username, email, password } = req.body;

  //check for username and email that they are avilable or not
  // method 1
  if (!username && !email) {
    throw new ApiError(400, "username or email is required ");
  }

  // method 2

  // Here is an alternative of above code based on logic discussed in video:
  // if (!(username || email)) {
  //   throw new ApiError(400, "username or email is required");
  // }

  //find the user is available in database or not
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  //check user is exist or not
  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  //store the method of user password correct or not in a variable
  // while using out custom methods we use user instead or User as it is the name of the model that is stored in the database and it consist of the mongoose function (like findOne, updateone etc)
  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid User credentials");
  }

  const { accessToken, refreshToken } = await generateAccessandRefreshTokens(
    user._id
  );

  // use of select we can customise that password and refreshToken field will not include
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // means cookies will modify only by the server not by the frontend
  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged In Successfully"
      )
    );
});

const logOutUser = asyncHandler(async (req, res) => {
  // for logout we have to clear the refresh token from the user
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User is logged Out successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  //store the incomming refresh token by cookies

  const incommingRefreshToken =
    req.cookie.refreshToken || req.body.refreshToken;

  if (incommingRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }
  try {
    // verify with the jwt token and decode the token
    const decodedToken = jwt.verify(
      incommingRefreshToken,
      process.env.ACCESS_TOKEN_SECRET
    );

    const user = User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "unauthorized request");
    }

    /**
     * check the incomming refresh token with the user refresh token
     * If they are not equal then we throw an error
     * If they are equal then we generate the new access token
     */

    if (incommingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or in used");
    }

    //and if the refresh token will match then generate the new access and refresh token to the user

    const options = {
      httpOnly: true,
      secure: true,
    };

    //call the function to generate the new access and refresh token
    const { accessToken, newRefreshToken } =
      await generateAccessandRefreshTokens(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          201,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

export { registerUser, loginUser, logOutUser, getAllUser, refreshAccessToken };
