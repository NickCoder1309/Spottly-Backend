// tests/unit/user.update.test.ts
import { updateAUser } from "../../src/controller/user";
import * as userService from "../../src/services/user";
import bcrypt from "bcrypt";
import httpMocks from "node-mocks-http";
import { Request, Response } from "express";

jest.mock("../../src/services/user");
jest.mock("bcrypt");

const mockUpdateUser = userService.updateUser as jest.Mock;
const mockHash = bcrypt.hash as jest.Mock;

describe("updateAUser controller - unit", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should update user successfully with valid fields", async () => {
    const fakeUpdatedUser = {
      id: "1",
      name: "John",
      email: "john@example.com",
    };
    mockUpdateUser.mockResolvedValueOnce(fakeUpdatedUser);

    const req = httpMocks.createRequest({
      method: "PUT",
      params: { userId: "1" },
      body: { name: "John", email: "john@example.com" },
    });
    const res = httpMocks.createResponse();

    await updateAUser(req as Request, res as unknown as Response);

    expect(mockUpdateUser).toHaveBeenCalledWith("1", {
      name: "John",
      email: "john@example.com",
    });
    expect(res.statusCode).toBe(200);
    const data = res._getJSONData();
    expect(data.message).toMatch(/update successful/i);
    expect(data.updatedUser).toEqual(fakeUpdatedUser);
  });

  it("should hash password if provided", async () => {
    mockHash.mockResolvedValueOnce("hashedpassword123");
    const fakeUpdatedUser = { id: "2", password: "hashedpassword123" };
    mockUpdateUser.mockResolvedValueOnce(fakeUpdatedUser);

    const req = httpMocks.createRequest({
      method: "PUT",
      params: { userId: "2" },
      body: { password: "mypassword123" },
    });
    const res = httpMocks.createResponse();

    await updateAUser(req as Request, res as Response);

    expect(mockHash).toHaveBeenCalledWith("mypassword123", 10);
    expect(mockUpdateUser).toHaveBeenCalledWith("2", {
      password: "hashedpassword123",
    });
    expect(res.statusCode).toBe(200);
  });

  it("should handle updateUser throwing an error", async () => {
    mockUpdateUser.mockRejectedValueOnce(new Error("DB failed"));

    const req = httpMocks.createRequest({
      method: "PUT",
      params: { userId: "99" },
      body: { name: "Error User" },
    });
    const res = httpMocks.createResponse();

    await updateAUser(req as Request, res as Response);

    expect(res.statusCode).toBe(500);
    const body = res._getJSONData();
    expect(body.error).toMatch(/db failed/i);
  });

  it("should skip password hashing if password is too short", async () => {
    const fakeUpdatedUser = { id: "3", username: "shortpass" };
    mockUpdateUser.mockResolvedValueOnce(fakeUpdatedUser);

    const req = httpMocks.createRequest({
      method: "PUT",
      params: { userId: "3" },
      body: { username: "shortpass", password: "123" },
    });
    const res = httpMocks.createResponse();

    await updateAUser(req as Request, res as Response);

    expect(mockHash).not.toHaveBeenCalled();
    expect(mockUpdateUser).toHaveBeenCalledWith("3", {
      username: "shortpass",
    });
    expect(res.statusCode).toBe(200);
  });
});
