declare namespace Express {
  interface Request {
    user: { _id: string; username: string; email: string; __v?: number };
  }
}
