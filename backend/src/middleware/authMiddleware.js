import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import User from "../models/auth/UserModel.js";

export const protect = asyncHandler(async (req, res, next) => {
  try {
    // Check if user is logged in
    const token = req.cookies.token;

    if (!token) {
      // 401 Unauthorized
      return res.status(401).json({ message: "Not authorized, please login!" });
    }

    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user details from the token, excluding the password
    const user = await User.findById(decoded.id).select("-password");

    // Check if user exists
    if (!user) {
      return res.status(404).json({ message: "User not found!" });
    }

    // Set user details in the request object
    req.user = user;

    next();
  } catch (error) {
    // 401 Unauthorized
    return res.status(401).json({ message: "Not authorized, token failed!" });
  }
});

// Admin middleware
export const adminMiddleware = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    // If user is admin, move to the next middleware/controller
    return next();
  }
  // If not admin, send 403 Forbidden
  return res.status(403).json({ message: "Only admins can do this!" });
});

// Creator middleware
export const creatorMiddleware = asyncHandler(async (req, res, next) => {
  if (
    (req.user && req.user.role === "creator") ||
    (req.user && req.user.role === "admin")
  ) {
    // If user is creator or admin, move to the next middleware/controller
    return next();
  }
  // If not creator, send 403 Forbidden
  return res.status(403).json({ message: "Only creators can do this!" });
});

// Verified middleware
export const verifiedMiddleware = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    // If user is verified, move to the next middleware/controller
    return next();
  }
  // If not verified, send 403 Forbidden
  return res.status(403).json({ message: "Please verify your email address!" });
});
