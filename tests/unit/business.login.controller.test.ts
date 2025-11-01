jest.mock("../../src/services/business");
jest.mock("bcrypt");
jest.mock("../../src/services/auth");

import { loginBusiness } from "../../src/controller/business";
import httpMocks from "node-mocks-http";
import * as businessService from "../../src/services/business";
import bcrypt from "bcrypt";
import { generateToken } from "../../src/services/auth";
import { Request, Response } from "express";

const mockGetBusinessByEmail = businessService.getBusinessByEmail as jest.Mock;
const mockCompare = bcrypt.compare as jest.Mock;
const mockGenerateToken = generateToken as jest.Mock;

describe("loginBusiness controller - unit", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 400 if email or password is missing", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "test@biz.com" }, // missing password
    });
    const res = httpMocks.createResponse();

    await loginBusiness(req as Request, res as Response);

    expect(res.statusCode).toBe(400);
    const body = res._getJSONData();
    expect(body.error).toMatch(/missing parameters/i);
  });

  it("should return 404 if business is not found", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce(null);

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "noone@biz.com", password: "test" },
    });
    const res = httpMocks.createResponse();

    await loginBusiness(req as Request, res as Response);

    expect(mockGetBusinessByEmail).toHaveBeenCalledWith("noone@biz.com");
    expect(res.statusCode).toBe(404);
    const body = res._getJSONData();
    expect(body.error).toMatch(/business not found/i);
  });

  it("should return 400 if password is incorrect", async () => {
    const fakeBusiness = {
      id: "1",
      email: "biz@example.com",
      username: "mybiz",
      password: "hashedpass",
    };
    mockGetBusinessByEmail.mockResolvedValueOnce(fakeBusiness);
    mockCompare.mockResolvedValueOnce(false);

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "biz@example.com", password: "wrongpass" },
    });
    const res = httpMocks.createResponse();

    await loginBusiness(req as Request, res as Response);

    expect(bcrypt.compare).toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    const body = res._getJSONData();
    expect(body.error).toMatch(/incorrect password/i);
  });

  it("should return 200 and token if login successful", async () => {
    const fakeBusiness = {
      id: "1",
      email: "biz@example.com",
      username: "mybiz",
      name: "My Biz",
      password: "hashedpass",
      busi_username: "mybiz",
      category: "Restaurant",
      rating: 4.5,
      description: "Tasty food",
      address: "123 Main St",
    };
    mockGetBusinessByEmail.mockResolvedValueOnce(fakeBusiness);
    mockCompare.mockResolvedValueOnce(true);
    mockGenerateToken.mockReturnValue("fake-token");

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "biz@example.com", password: "correctpass" },
    });
    const res = httpMocks.createResponse();

    await loginBusiness(req as Request, res as Response);

    expect(mockGenerateToken).toHaveBeenCalledWith({
      id: "1",
      email: "biz@example.com",
      username: "mybiz",
    });
    expect(res.statusCode).toBe(200);
    const body = res._getJSONData();
    expect(body.message).toMatch(/login successful/i);
    expect(body.token).toBe("fake-token");
    expect(body.user.email).toBe("biz@example.com");
  });

  it("should return 500 if an exception is thrown", async () => {
    mockGetBusinessByEmail.mockRejectedValueOnce(new Error("DB error"));

    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "biz@example.com", password: "whatever" },
    });
    const res = httpMocks.createResponse();

    await loginBusiness(req as Request, res as Response);

    expect(res.statusCode).toBe(500);
    const body = res._getJSONData();
    expect(body.error).toMatch(/server error/i);
  });
});
