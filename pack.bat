"C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\MSBuild\15.0\Bin\MSBuild.exe" /t:Build  /p:Configuration="Release";Platform="any cpu"
del *.nupkg /Q
nuget pack -properties Configuration=Release
