import { registerUser } from "../../src/controller/user";
import httpMocks from "node-mocks-http";
import * as userService from "../../src/services/user";
import { Request, Response } from "express";

jest.mock("../../src/services/user");

const mockCreateUser = userService.createUser as jest.Mock;
const mockGetUserByEmail = userService.getUserByEmail as jest.Mock;
const mockGetUserByUsername = userService.getUserByUsername as jest.Mock;

describe("registerUser controller - unit", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 400 when required fields are missing", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: { email: "a@b.com", name: "John" }, // missing age and password
    });
    const res = httpMocks.createResponse();
    await registerUser(req as Request, res as Response);
    expect(res.statusCode).toBe(400);
    const body = res._getJSONData();
    expect(body.error).toMatch(/Faltan campos obligatorios/i);
  });

  it("should register a user successfully", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: {
        email: "test@example.com",
        name: "John",
        age: 25,
        password: "abc12345",
        username: "johnny",
        surname: "Doe",
      },
    });
    const res = httpMocks.createResponse();

    // mocks: no usuario existente, createUser retorna el usuario creado
    mockGetUserByEmail.mockResolvedValueOnce(null);
    mockGetUserByUsername.mockResolvedValueOnce(null);
    mockCreateUser.mockResolvedValueOnce({
      id: "u1",
      email: "test@example.com",
      username: "johnny",
      name: "John",
      age: 25,
    });

    await registerUser(req as Request, res as Response);

    expect(mockGetUserByEmail).toHaveBeenCalledWith("test@example.com");
    expect(mockGetUserByUsername).toHaveBeenCalledWith("johnny");
    expect(mockCreateUser).toHaveBeenCalled(); // puedes comprobar args exactos
    expect(res.statusCode).toBe(201);
    const body = res._getJSONData();
    expect(body.email).toBe("test@example.com");
    expect(body.username).toBe("johnny");
  });

  it("should return 409 if email or username already exists", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: {
        email: "exists@example.com",
        name: "John",
        age: 30,
        password: "abc12345",
        username: "exists",
        surname: "X",
      },
    });
    const res = httpMocks.createResponse();

    mockGetUserByEmail.mockResolvedValueOnce({
      id: "u1",
      email: "exists@example.com",
    });
    mockGetUserByUsername.mockResolvedValueOnce(null);

    await registerUser(req as Request, res as Response);

    expect(res.statusCode).toBe(409);
    const body = res._getJSONData();
    expect(body.error).toMatch(/ya está registrado/i);
  });

  it("should return 400 for invalid email", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: {
        email: "bad-email",
        name: "n",
        age: 20,
        password: "abc12345",
        username: "u",
        surname: "s",
      },
    });
    const res = httpMocks.createResponse();

    await registerUser(req as Request, res as Response);
    expect(res.statusCode).toBe(400);
  });

  it("should return 400 for weak password", async () => {
    const req = httpMocks.createRequest({
      method: "POST",
      body: {
        email: "a@b.com",
        name: "John",
        age: 22,
        password: "short",
        username: "u2",
        surname: "s",
      },
    });
    const res = httpMocks.createResponse();

    await registerUser(req as Request, res as Response);
    expect(res.statusCode).toBe(400);
    const body = res._getJSONData();
    expect(body.error).toMatch(/contraseña/i);
  });
});
