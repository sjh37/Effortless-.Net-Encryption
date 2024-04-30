"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" /t:Build  /p:Configuration="Release";Platform="any cpu"
del *.nupkg /Q
nuget pack -properties Configuration=Release
