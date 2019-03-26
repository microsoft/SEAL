# Creating a NuGet package

After building `dotnet\src\SEALNet.csproj` you can create a NuGet package that you can
use to easily add Microsoft SEAL capabilities to all of your .NET projects. Currently
the NuGet package is only supported in Windows.

You will need to:
1. Compile binaries
    1. `native\src\SEAL.vcxproj`
    2. `dotnet\native\SEALNetNative.vcxproj`
    3. `dotnet\src\SEALNet.csproj`
3. [Download the NuGet command line tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe)
4. Run the command below to create NuGet package
5. Add NuGet package reference to your .NET projects

The command to create the NuGet package after compiling binaries is the following:

````
cd dotnet\nuget
nuget.exe pack SEALNet.nuspec -properties Configuration=Release -Verbosity detailed -OutputDir Release
cd ..\..
````

After the package is created, copy it from `dotnet\nuget\Release` to a known location (e.g., `C:\NuGetPackages`).

To add a reference to the NuGet package, you will need to configure Visual Studio so it can find
packages in this known location. In Microsoft Visual Studio 2017, for example, you can:
1. Select the menu uption `Tools / Options...`
2. On the left pane of the Options dialog, navigate to `NuGet Package Manager / Package Sources`
3. On the right pane of the Options dialog, add a new package source that points to the directory
   where you copied the NuGet package (e.g., `C:\NuGetPackages`)

After this, you should be able to add a reference to this package in your own .NET project. After
creating or opening your project in Visual Studio, you can right click on the project in the
Solution Explorer window, and select `Manage NuGet packages...`. In the window that appears
you will be able to select the `Microsoft.Research.SEAL` NuGet package to add to your project.