/* the one version number: the Makefile checks that Info.plist and the
   package control file agree with it */
#define LR_VERSION "1.0.3"
#define LR_BUILD_NUMBER "102"
/* who makes it: About and the package carry this name */
#define LR_DEVELOPER "LegacyReborn Project"
/* where releases are published: the update checker asks the github api for
   the latest release of this repository and offers its .deb, which installs
   as root. it has to be an account the project owns: a name nobody holds can
   be registered by anyone, and their release would reach every phone */
#define LR_GITHUB_REPO "LR-Vensuki/LegacyRay"
