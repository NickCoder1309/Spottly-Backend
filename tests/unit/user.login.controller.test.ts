// tests/unit/loginUser.test.ts

jest.mock("../../src/services/user");
jest.mock("bcrypt");
jest.mock("../../src/services/auth");

import { loginUser } from "../../src/controller/user";
import httpMocks from "node-mocks-http";
import * as userService from "../../src/services/user";
import bcrypt from "bcrypt";
import { generateToken } from "../../src/services/auth";
import { Request, Response } from "express";

const mockGetUserByEmail = userService.getUserByEmail as jest.Mock;
const mockCompare = bcrypt.compare as jest.Mock;
const mockGenerateToken = generateToken as jest.Mock;

describe("loginUser controller - unit", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 400 if email or password is missing", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "test@example.com" }, // missing password
    });
    const res = httpMocks.createResponse();

    await loginUser(req as unknown as Request, res as unknown as Response);

    expect(res.statusCode).toBe(400);
    const body = res._getJSONData();
    expect(body.error).toMatch(/missing parameters/i);
  });

  it("should return 404 if user is not found", async () => {
    mockGetUserByEmail.mockResolvedValueOnce(null);

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "noone@example.com", password: "test" },
    });
    const res = httpMocks.createResponse();

    await loginUser(req as unknown as Request, res as unknown as Response);

    expect(mockGetUserByEmail).toHaveBeenCalledWith("noone@example.com");
    expect(res.statusCode).toBe(404);
    const body = res._getJSONData();
    expect(body.error).toMatch(/user not found/i);
  });

  it("should return 400 if password is incorrect", async () => {
    const fakeUser = {
      id: "1",
      email: "test@example.com",
      username: "johnny",
      password: "hashedpass",
    };
    mockGetUserByEmail.mockResolvedValueOnce(fakeUser);
    mockCompare.mockResolvedValueOnce(false); // password invalid

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "test@example.com", password: "wrong" },
    });
    const res = httpMocks.createResponse();

    await loginUser(req as unknown as Request, res as unknown as Response);

    expect(bcrypt.compare).toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    const body = res._getJSONData();
    expect(body.error).toMatch(/incorrect password/i);
  });

  it("should return 200 and token if login successful", async () => {
    const fakeUser = {
      id: "1",
      email: "test@example.com",
      username: "johnny",
      name: "John",
      password: "hashedpass",
    };
    mockGetUserByEmail.mockResolvedValueOnce(fakeUser);
    mockCompare.mockResolvedValueOnce(true);
    mockGenerateToken.mockReturnValue("fake-token");

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "test@example.com", password: "correctpass" },
    });
    const res = httpMocks.createResponse();

    await loginUser(req as unknown as Request, res as unknown as Response);

    expect(mockGenerateToken).toHaveBeenCalledWith({
      id: "1",
      email: "test@example.com",
      username: "johnny",
    });
    expect(res.statusCode).toBe(200);
    const body = res._getJSONData();
    expect(body.message).toMatch(/login successful/i);
    expect(body.token).toBe("fake-token");
    expect(body.user.email).toBe("test@example.com");
  });

  it("should return 500 if an exception is thrown", async () => {
    mockGetUserByEmail.mockRejectedValueOnce(new Error("DB error"));

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "test@example.com", password: "whatever" },
    });
    const res = httpMocks.createResponse();

    await loginUser(req as unknown as Request, res as unknown as Response);

    expect(res.statusCode).toBe(500);
    const body = res._getJSONData();
    expect(body.error).toMatch(/server error/i);
  });
});
