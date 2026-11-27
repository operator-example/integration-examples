FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/CsharpEd25519Example/CsharpEd25519Example.csproj src/CsharpEd25519Example/
RUN dotnet restore src/CsharpEd25519Example/CsharpEd25519Example.csproj
COPY src/ src/
RUN dotnet publish src/CsharpEd25519Example/CsharpEd25519Example.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "CsharpEd25519Example.dll"]
