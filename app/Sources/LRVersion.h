/* the one version number: the Makefile checks that Info.plist and the
   package control file agree with it */
#define LR_VERSION "1.0.4"
#define LR_BUILD_NUMBER "103"
/* who makes it: About and the package carry this name */
#define LR_DEVELOPER "LegacyReborn Project"
/* where releases are published: the update checker asks the github api for
   the latest release of this repository and offers its .deb, which installs
   as root. it has to be an account the project owns: a name nobody holds can
   be registered by anyone, and their release would reach every phone */
#if defined(LR_MACOS)
/* the mac build ships from its own repository: LegacyRay-<version>-mac.zip */
#define LR_GITHUB_REPO "LR-Vensuki/LegacyRay-Mac"
#else
#define LR_GITHUB_REPO "LR-Vensuki/LegacyRay"
#endif
