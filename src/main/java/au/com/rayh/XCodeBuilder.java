/*
 * The MIT License
 *
 * Copyright (c) 2011 Ray Yamamoto Hilton
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package au.com.rayh;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;
import com.google.common.collect.Lists;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.CopyOnWriteList;
import hudson.util.QuotedStringTokenizer;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.FileFilter;
import java.io.IOException;
import java.io.ObjectStreamException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

/**
 * @author Ray Hilton
 */
public class XCodeBuilder extends Builder {

    private static final int SIGTERM = 143;

    private static final String MANIFEST_PLIST_TEMPLATE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
            + "<plist version=\"1.0\"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${IPA_URL_BASE}/${IPA_NAME}</string></dict></array>"
            + "<key>metadata</key><dict><key>bundle-identifier</key><string>${BUNDLE_ID}</string><key>bundle-version</key><string>${BUNDLE_VERSION}</string><key>kind</key><string>software</string><key>title</key><string>${APP_NAME}</string></dict></dict></array></dict></plist>";
    /**
     * @since 1.0
     */
    public final Boolean cleanBeforeBuild;
    /**
     * @since 1.3
     */
    public final Boolean cleanTestReports;
    /**
     * @since 1.0
     */
    public final String configuration;
    /**
     * @since 1.0
     */
    public final String target;
    /**
     * @since 1.0
     */
    public final String sdk;
    /**
     * @since 1.0
     */
    public final String xcodeProjectPath;
    /**
     * @since 1.0
     */
    public final String xcodeProjectFile;
    /**
     * @since 1.3
     */
    public final String xcodebuildArguments;
    /**
     * @since 1.2
     */
    public final String xcodeSchema;
    /**
     * @since 1.2
     */
    public final String xcodeWorkspaceFile;
    /**
     * @since 1.0
     */
    public final String cfBundleVersionValue;
    /**
     * @since 1.0
     */
    public final String cfBundleShortVersionStringValue;
    /**
     * @since 1.0
     */
    public final Boolean buildIpa;
    /**
     * @since 1.0
     */
    public final Boolean generateArchive;
    /**
     * @since 1.5
     **/
    public final Boolean unlockKeychain;
    /**
     * @since 1.4
     */
    public final String keychainName;
    /**
     * @since 1.0
     */
    public final String keychainPath;
    /**
     * @since 1.0
     */
    public final String keychainPwd;
    /**
     * @since 1.3.3
     */
    public final String codeSigningIdentity;
    /**
     * @since 1.4
     */
    public final Boolean allowFailingBuildResults;
    /**
     * @since 1.4
     */
    public final String ipaName;
    /**
     * @since 1.4
     */
    public final String ipaOutputDirectory;
    /**
     * @since 1.4
     */
    public Boolean provideApplicationVersion;
    /**
     * @since 1.4
     */
    public final Boolean changeBundleID;
    /**
     * @since 1.4
     */
    public final String bundleID;
    /**
     * @since 1.4
     */
    public final String bundleIDInfoPlistPath;

    public final Boolean interpretTargetAsRegEx;
    /**
     * @since 1.5
     */
    public final String ipaManifestPlistUrl;

    public final String artifactsOutputDirectory;
    public final String archivesOutputDirectory;
    public final String archiveFileName;
    public final String exportTeamId;
    public final String exportMethod;

    // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
    @DataBoundConstructor
    public XCodeBuilder(Boolean buildIpa, Boolean generateArchive, Boolean cleanBeforeBuild, Boolean cleanTestReports, String configuration,
    		String target, String sdk, String xcodeProjectPath, String xcodeProjectFile, String xcodebuildArguments,
    		String cfBundleVersionValue, String cfBundleShortVersionStringValue, Boolean unlockKeychain,
    		String keychainName, String keychainPath, String keychainPwd, String xcodeWorkspaceFile,
    		String xcodeSchema, String codeSigningIdentity, Boolean allowFailingBuildResults,
    		String ipaName, Boolean provideApplicationVersion, String ipaOutputDirectory, Boolean changeBundleID, String bundleID,
    		String bundleIDInfoPlistPath, String ipaManifestPlistUrl, Boolean interpretTargetAsRegEx,
            String artifactsOutputDirectory, String archivesOutputDirectory, String archiveFileName,
            String exportTeamId, String exportMethod) {

        this.buildIpa = buildIpa;
        this.generateArchive = generateArchive;
        this.sdk = sdk;
        this.target = target;
        this.cleanBeforeBuild = cleanBeforeBuild;
        this.cleanTestReports = cleanTestReports;
        this.configuration = configuration;
        this.xcodeProjectPath = xcodeProjectPath;
        this.xcodeProjectFile = xcodeProjectFile;
        this.xcodebuildArguments = xcodebuildArguments;
        this.keychainName = keychainName;
        this.xcodeWorkspaceFile = xcodeWorkspaceFile;
        this.xcodeSchema = xcodeSchema;
        this.codeSigningIdentity = codeSigningIdentity;
        this.cfBundleVersionValue = cfBundleVersionValue;
        this.cfBundleShortVersionStringValue = cfBundleShortVersionStringValue;
        this.unlockKeychain = unlockKeychain;
        this.keychainPath = keychainPath;
        this.keychainPwd = keychainPwd;
        this.allowFailingBuildResults = allowFailingBuildResults;
        this.ipaName = ipaName;
        this.ipaOutputDirectory = ipaOutputDirectory;
        this.provideApplicationVersion = provideApplicationVersion;
        this.changeBundleID = changeBundleID;
        this.bundleID = bundleID;
        this.bundleIDInfoPlistPath = bundleIDInfoPlistPath;
        this.interpretTargetAsRegEx = interpretTargetAsRegEx;
        this.ipaManifestPlistUrl = ipaManifestPlistUrl;
        this.artifactsOutputDirectory = artifactsOutputDirectory;
        this.archivesOutputDirectory = archivesOutputDirectory;
        this.archiveFileName = archiveFileName;
        this.exportTeamId = exportTeamId;
        this.exportMethod = exportMethod;
    }

    @SuppressWarnings("unused")
    private Object readResolve() throws ObjectStreamException {
        if (provideApplicationVersion == null) {
            if (!StringUtils.isEmpty(cfBundleVersionValue)
                || !StringUtils.isEmpty(cfBundleShortVersionStringValue)) {
                provideApplicationVersion = true;
            }
        }
        return this;
    }

    private FilePath resolvePath(String directory, FilePath defaultPath) throws IOException, InterruptedException {
        return resolvePath(directory, defaultPath, true);
    }
 
    private FilePath resolvePath(String directory, FilePath defaultPath, boolean autoCreate) throws IOException, InterruptedException {
        if (directory == null || StringUtils.isEmpty(directory)) {
            return defaultPath;
        }

        FilePath path = defaultPath.child(directory);
        if (autoCreate && !path.exists()) {
            path.mkdirs();
        }

        return path;
    }

    private List<FilePath> listRecursive(FilePath path, final FileFilter filter) throws IOException, InterruptedException {
        List<FilePath> list = new ArrayList<FilePath>();

        list.addAll(path.list(filter));

        for (FilePath subdirectory : path.listDirectories()) {
            list.addAll(listRecursive(subdirectory, filter));
        }

        return list;
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) throws InterruptedException, IOException {
        EnvVars envs = build.getEnvironment(listener);
        FilePath projectRoot = build.getWorkspace();

        // check that the configured tools exist
        if (!new FilePath(projectRoot.getChannel(), getGlobalConfiguration().getXcodebuildPath()).exists()) {
            listener.fatalError(Messages.XCodeBuilder_xcodebuildNotFound(getGlobalConfiguration().getXcodebuildPath()));
            return false;
        }
        if (!new FilePath(projectRoot.getChannel(), getGlobalConfiguration().getAgvtoolPath()).exists()) {
            listener.fatalError(Messages.XCodeBuilder_avgtoolNotFound(getGlobalConfiguration().getAgvtoolPath()));
            return false;
        }

        // Start expanding all string variables in parameters
        // NOTE: we currently use variable shadowing to avoid having to rewrite all code (and break pull requests), this will be cleaned up at later stage.
        String configuration = envs.expand(this.configuration);
        String target = envs.expand(this.target);
        String sdk = envs.expand(this.sdk);
        String xcodeProjectPath = envs.expand(this.xcodeProjectPath);
        String xcodeProjectFile = envs.expand(this.xcodeProjectFile);
        String xcodebuildArguments = envs.expand(this.xcodebuildArguments);
        String xcodeSchema = envs.expand(this.xcodeSchema);
        String xcodeWorkspaceFile = envs.expand(this.xcodeWorkspaceFile);
        String cfBundleVersionValue = envs.expand(this.cfBundleVersionValue);
        String cfBundleShortVersionStringValue = envs.expand(this.cfBundleShortVersionStringValue);
        String codeSigningIdentity = envs.expand(this.codeSigningIdentity);
        String ipaName = envs.expand(this.ipaName);
        String ipaOutputDirectory = envs.expand(this.ipaOutputDirectory);
        String bundleID = envs.expand(this.bundleID);
        String bundleIDInfoPlistPath = envs.expand(this.bundleIDInfoPlistPath);
        String ipaManifestPlistUrl = envs.expand(this.ipaManifestPlistUrl);
        String artifactsOutputDirectory = envs.expand(this.artifactsOutputDirectory);
        String archivesOutputDirectory = envs.expand(this.archivesOutputDirectory);
        String archiveFileName = envs.expand(this.archiveFileName);
        String exportTeamId = envs.expand(this.exportTeamId);
        String exportMethod = envs.expand(this.exportMethod);
        // End expanding all string variables in parameters  

        // Set the working directory
        if (!StringUtils.isEmpty(xcodeProjectPath)) {
            projectRoot = projectRoot.child(xcodeProjectPath);
        }
        listener.getLogger().println(Messages.XCodeBuilder_workingDir(projectRoot));

        // Infer as best we can the build platform
        String buildPlatform = "iphoneos";
        if (!StringUtils.isEmpty(sdk)) {
            if (StringUtils.contains(sdk.toLowerCase(), "iphonesimulator")) {
                // Building for the simulator
                buildPlatform = "iphonesimulator";
            }
        }

        // Normalize xcodeProjectFile
        if (!StringUtils.isEmpty(xcodeProjectFile) && !xcodeProjectFile.endsWith(".xcodeproj"))
            xcodeProjectFile = xcodeProjectFile + ".xcodeproj";

        // Normalize xcodeWorkspaceFile
        if (!StringUtils.isEmpty(xcodeWorkspaceFile) && !xcodeWorkspaceFile.endsWith(".xcworkspace"))
            xcodeWorkspaceFile = xcodeWorkspaceFile + ".xcworkspace";

        // Artifacts output path
        FilePath artifactsOutputPath = resolvePath(artifactsOutputDirectory, projectRoot);

        // XCode archive name
        if (archiveFileName == null || StringUtils.isEmpty(archiveFileName))
            archiveFileName = "${JOB_NAME}";
        archiveFileName = envs.expand(archiveFileName);
        if (!archiveFileName.endsWith(".xcarchive")) {
            archiveFileName = archiveFileName + ".xcarchive";
        }

        // XCode archive location
        FilePath archivesOutputPath = resolvePath(archivesOutputDirectory, artifactsOutputPath);
        FilePath archiveLocation = archivesOutputPath.child(archiveFileName);
        if (archiveLocation.exists()) {
            archiveLocation.deleteRecursive();
        }

        // XCode Version
        int returnCode = launcher.launch().envs(envs).cmds(getGlobalConfiguration().getXcodebuildPath(), "-version").stdout(listener).pwd(projectRoot).join();
        if (returnCode > 0) {
            listener.fatalError(Messages.XCodeBuilder_xcodeVersionNotFound());
            return false; // We fail the build if XCode isn't deployed
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // Try to read CFBundleShortVersionString from project
        listener.getLogger().println(Messages.XCodeBuilder_fetchingCFBundleShortVersionString());
        String cfBundleShortVersionString = "";
        returnCode = launcher.launch().envs(envs).cmds(getGlobalConfiguration().getAgvtoolPath(), "mvers", "-terse1").stdout(output).pwd(projectRoot).join();
        // only use this version number if we found it
        if (returnCode == 0)
            cfBundleShortVersionString = output.toString().trim();
        if (StringUtils.isEmpty(cfBundleShortVersionString))
            listener.getLogger().println(Messages.XCodeBuilder_CFBundleShortVersionStringNotFound());
        else
            listener.getLogger().println(Messages.XCodeBuilder_CFBundleShortVersionStringFound(cfBundleShortVersionString));
        listener.getLogger().println(Messages.XCodeBuilder_CFBundleShortVersionStringValue(cfBundleShortVersionString));

        output.reset();

        // Try to read CFBundleVersion from project
        listener.getLogger().println(Messages.XCodeBuilder_fetchingCFBundleVersion());
        String cfBundleVersion = "";
        returnCode = launcher.launch().envs(envs).cmds(getGlobalConfiguration().getAgvtoolPath(), "vers", "-terse").stdout(output).pwd(projectRoot).join();
        // only use this version number if we found it
        if (returnCode == 0)
            cfBundleVersion = output.toString().trim();
        if (StringUtils.isEmpty(cfBundleVersion))
            listener.getLogger().println(Messages.XCodeBuilder_CFBundleVersionNotFound());
        else
            listener.getLogger().println(Messages.XCodeBuilder_CFBundleVersionFound(cfBundleVersion));
        listener.getLogger().println(Messages.XCodeBuilder_CFBundleVersionValue(cfBundleVersion));

        String buildDescription = cfBundleShortVersionString + " (" + cfBundleVersion + ")";
        XCodeAction a = new XCodeAction(buildDescription);
        build.addAction(a);

        // Update the bundle ID
        if (this.changeBundleID != null && this.changeBundleID) {
        	listener.getLogger().println(Messages.XCodeBuilder_CFBundleIdentifierChanged(bundleIDInfoPlistPath, bundleID));
        	returnCode = launcher.launch().envs(envs).cmds("/usr/libexec/PlistBuddy", "-c",  "Set :CFBundleIdentifier " + bundleID, bundleIDInfoPlistPath).stdout(listener).pwd(projectRoot).join();

        	if (returnCode > 0) {
        		listener.fatalError(Messages.XCodeBuilder_CFBundleIdentifierInfoPlistNotFound(bundleIDInfoPlistPath));
        		return false;
        	}
        }

        // Update the Marketing version (CFBundleShortVersionString)
        if (this.provideApplicationVersion != null && this.provideApplicationVersion && !StringUtils.isEmpty(cfBundleShortVersionStringValue)) {
            try {
                // If not empty we use the Token Expansion to replace it
                // https://wiki.jenkins-ci.org/display/JENKINS/Token+Macro+Plugin
                cfBundleShortVersionString = TokenMacro.expandAll(build, listener, cfBundleShortVersionStringValue);
                listener.getLogger().println(Messages.XCodeBuilder_CFBundleShortVersionStringUpdate(cfBundleShortVersionString));
                returnCode = launcher.launch().envs(envs).cmds(getGlobalConfiguration().getAgvtoolPath(), "new-marketing-version", cfBundleShortVersionString).stdout(listener).pwd(projectRoot).join();
                if (returnCode > 0) {
                    listener.fatalError(Messages.XCodeBuilder_CFBundleShortVersionStringUpdateError(cfBundleShortVersionString));
                    return false;
                }
            } catch (MacroEvaluationException e) {
                listener.fatalError(Messages.XCodeBuilder_CFBundleShortVersionStringMacroError(e.getMessage()));
                // Fails the build
                return false;
            }
        }

        // Update the Technical version (CFBundleVersion)
        if (this.provideApplicationVersion != null && this.provideApplicationVersion && !StringUtils.isEmpty(cfBundleVersionValue)) {
            try {
                // If not empty we use the Token Expansion to replace it
                // https://wiki.jenkins-ci.org/display/JENKINS/Token+Macro+Plugin
                cfBundleVersion = TokenMacro.expandAll(build, listener, cfBundleVersionValue);
                listener.getLogger().println(Messages.XCodeBuilder_CFBundleVersionUpdate(cfBundleVersion));
                returnCode = launcher.launch().envs(envs).cmds(getGlobalConfiguration().getAgvtoolPath(), "new-version", "-all", cfBundleVersion).stdout(listener).pwd(projectRoot).join();
                if (returnCode > 0) {
                    listener.fatalError(Messages.XCodeBuilder_CFBundleVersionUpdateError(cfBundleVersion));
                    return false;
                }
            } catch (MacroEvaluationException e) {
                listener.fatalError(Messages.XCodeBuilder_CFBundleVersionMacroError(e.getMessage()));
                // Fails the build
                return false;
            }
        }

        listener.getLogger().println(Messages.XCodeBuilder_CFBundleShortVersionStringUsed(cfBundleShortVersionString));
        listener.getLogger().println(Messages.XCodeBuilder_CFBundleVersionUsed(cfBundleVersion));

        // remove test-reports and *.ipa
        if (cleanTestReports != null && cleanTestReports) {
            listener.getLogger().println(Messages.XCodeBuilder_cleaningTestReportsDir(projectRoot.child("test-reports").absolutize().getRemote()));
            projectRoot.child("test-reports").deleteRecursive();
		}

        if (unlockKeychain != null && unlockKeychain) {
            // Let's unlock the keychain
            Keychain keychain = getKeychain();
            if(keychain == null)
            {
                listener.fatalError(Messages.XCodeBuilder_keychainNotConfigured());
                return false;
            }
            String keychainPath = envs.expand(keychain.getKeychainPath());
            String keychainPwd = envs.expand(keychain.getKeychainPassword());
            launcher.launch().envs(envs).cmds("/usr/bin/security", "list-keychains", "-s", keychainPath).stdout(listener).pwd(projectRoot).join();
            launcher.launch().envs(envs).cmds("/usr/bin/security", "default-keychain", "-d", "user", "-s", keychainPath).stdout(listener).pwd(projectRoot).join();
            if (StringUtils.isEmpty(keychainPwd))
                returnCode = launcher.launch().envs(envs).cmds("/usr/bin/security", "unlock-keychain", keychainPath).stdout(listener).pwd(projectRoot).join();
            else
                returnCode = launcher.launch().envs(envs).cmds("/usr/bin/security", "unlock-keychain", "-p", keychainPwd, keychainPath).masks(false, false, false, true, false).stdout(listener).pwd(projectRoot).join();

            if (returnCode > 0) {
                listener.fatalError(Messages.XCodeBuilder_unlockKeychainFailed());
                return false;
            }

            // Show the keychain info after unlocking, if not, OS X will prompt for the keychain password
            launcher.launch().envs(envs).cmds("/usr/bin/security", "show-keychain-info", keychainPath).stdout(listener).pwd(projectRoot).join();
        }

        // display useful setup information
        listener.getLogger().println(Messages.XCodeBuilder_DebugInfoLineDelimiter());
        listener.getLogger().println(Messages.XCodeBuilder_DebugInfoAvailablePProfiles());
        /*returnCode =*/ launcher.launch().envs(envs).cmds("/usr/bin/security", "find-identity", "-p", "codesigning", "-v").stdout(listener).pwd(projectRoot).join();

        if (!StringUtils.isEmpty(codeSigningIdentity)) {
            listener.getLogger().println(Messages.XCodeBuilder_DebugInfoCanFindPProfile());
            /*returnCode =*/ launcher.launch().envs(envs).cmds("/usr/bin/security", "find-certificate", "-a", "-c", codeSigningIdentity, "-Z", "|", "grep", "^SHA-1").stdout(listener).pwd(projectRoot).join();
            // We could fail here, but this doesn't seem to work as it should right now (output not properly redirected. We might need a parser)
        }

        listener.getLogger().println(Messages.XCodeBuilder_DebugInfoAvailableSDKs());
        /*returnCode =*/ launcher.launch().envs(envs).cmds(getGlobalConfiguration().getXcodebuildPath(), "-showsdks").stdout(listener).pwd(projectRoot).join();

        XcodeBuildListParser xcodebuildListParser;
        {
            List<String> commandLine = Lists.newArrayList(getGlobalConfiguration().getXcodebuildPath());
            commandLine.add("-list");
            // xcodebuild -list -workspace $workspace
            listener.getLogger().println(Messages.XCodeBuilder_DebugInfoAvailableSchemes());
            if (!StringUtils.isEmpty(xcodeWorkspaceFile)) {
                commandLine.add("-workspace");
                commandLine.add(xcodeWorkspaceFile);
            } else if (!StringUtils.isEmpty(xcodeProjectFile)) {
                commandLine.add("-project");
                commandLine.add(xcodeProjectFile);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            returnCode = launcher.launch().envs(envs).cmds(commandLine).stdout(baos).pwd(projectRoot).start().joinWithTimeout(10, TimeUnit.SECONDS, listener);
            String xcodeBuildListOutput = baos.toString("UTF-8");
            listener.getLogger().println(xcodeBuildListOutput);
            boolean timedOut = returnCode == SIGTERM;
            if (returnCode > 0 && !timedOut) return false;

            xcodebuildListParser = new XcodeBuildListParser(xcodeBuildListOutput);
        }
        listener.getLogger().println(Messages.XCodeBuilder_DebugInfoLineDelimiter());

        // Build
        StringBuilder xcodeReport = new StringBuilder(Messages.XCodeBuilder_invokeXcodebuild());
        XCodeBuildOutputParser reportGenerator = new JenkinsXCodeBuildOutputParser(projectRoot, listener);
        List<String> commandLine = Lists.newArrayList(getGlobalConfiguration().getXcodebuildPath());

        // Prioritizing schema over target setting
        if (!StringUtils.isEmpty(xcodeSchema)) {
            commandLine.add("-scheme");
            commandLine.add(xcodeSchema);
            xcodeReport.append(", scheme: ").append(xcodeSchema);
        } else if (StringUtils.isEmpty(target) && !StringUtils.isEmpty(xcodeProjectFile)) {
            commandLine.add("-alltargets");
            xcodeReport.append("target: ALL");
        } else if(interpretTargetAsRegEx != null && interpretTargetAsRegEx) {
            if(xcodebuildListParser.getTargets().isEmpty()) {
                listener.getLogger().println(Messages.XCodeBuilder_NoTargetsFoundInConfig());
                return false;
            }
            Collection<String> matchedTargets = Collections2.filter(xcodebuildListParser.getTargets(),
                    Predicates.containsPattern(target));

            if (matchedTargets.isEmpty()) {
                listener.getLogger().println(Messages.XCodeBuilder_NoMatchingTargetsFound());
                return false;
            }

            for (String matchedTarget : matchedTargets) {
                commandLine.add("-target");
                commandLine.add(matchedTarget);
                xcodeReport.append("target: ").append(matchedTarget);
            }
        } else {
            commandLine.add("-target");
            commandLine.add(target);
            xcodeReport.append("target: ").append(target);
        }

        if (!StringUtils.isEmpty(sdk)) {
            commandLine.add("-sdk");
            commandLine.add(sdk);
            xcodeReport.append(", sdk: ").append(sdk);
        } else {
            xcodeReport.append(", sdk: DEFAULT");
        }

        // Prioritizing workspace over project setting
        if (!StringUtils.isEmpty(xcodeWorkspaceFile)) {
            commandLine.add("-workspace");
            commandLine.add(xcodeWorkspaceFile);
            xcodeReport.append(", workspace: ").append(xcodeWorkspaceFile);
        } else if (!StringUtils.isEmpty(xcodeProjectFile)) {
            commandLine.add("-project");
            commandLine.add(xcodeProjectFile);
            xcodeReport.append(", project: ").append(xcodeProjectFile);
        } else {
            xcodeReport.append(", project: DEFAULT");
        }

		if (!StringUtils.isEmpty(configuration)) {
			commandLine.add("-configuration");
			commandLine.add(configuration);
			xcodeReport.append(", configuration: ").append(configuration);
		}

        if (cleanBeforeBuild) {
            commandLine.add("clean");
            xcodeReport.append(", clean: YES");
        } else {
            xcodeReport.append(", clean: NO");
        }

        //Bug JENKINS-30362
        //Generating an archive builds the project twice
        //commandLine.add("build");
        if((generateArchive != null && generateArchive) || (buildIpa != null && buildIpa)) {
            commandLine.add("archive");
            commandLine.add("-archivePath");
            commandLine.add(archiveLocation.absolutize().getRemote());
            xcodeReport.append(", archive:YES");
        }else{
            xcodeReport.append(", archive:NO");
            commandLine.add("build");
        }
        //END Bug JENKINS-30362

        // handle code signing identities
        if (!StringUtils.isEmpty(codeSigningIdentity)) {
            commandLine.add("CODE_SIGN_IDENTITY=" + codeSigningIdentity);
            xcodeReport.append(", codeSignIdentity: ").append(codeSigningIdentity);
        } else {
            xcodeReport.append(", codeSignIdentity: DEFAULT");
        }

        // Additional (custom) xcodebuild arguments
        if (!StringUtils.isEmpty(xcodebuildArguments)) {
            commandLine.addAll(splitXcodeBuildArguments(xcodebuildArguments));
        }

        listener.getLogger().println(xcodeReport.toString());
        returnCode = launcher.launch().envs(envs).cmds(commandLine).stdout(reportGenerator.getOutputStream()).pwd(projectRoot).join();
        if (allowFailingBuildResults != null && !allowFailingBuildResults) {
            if (reportGenerator.getExitCode() != 0) return false;
            if (returnCode > 0) return false;
        }

        // Package IPA
        if (buildIpa) {

            if (!archiveLocation.exists() || !archiveLocation.isDirectory()) {
                listener.fatalError(Messages.XCodeBuilder_NotExistingArchiveDirectory(archiveLocation.absolutize().getRemote()));
                return false;
            }

            // Determine output path for IPA
            FilePath ipaOutputPath = resolvePath(ipaOutputDirectory, artifactsOutputPath);

            // Export archive options
            StringBuilder exportArchiveOptionsBuilder = new StringBuilder();
            exportArchiveOptionsBuilder.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            exportArchiveOptionsBuilder.append("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
            exportArchiveOptionsBuilder.append("<plist version=\"1.0\">\n");
            exportArchiveOptionsBuilder.append("<dict>\n");
            if (exportTeamId != null && !exportTeamId.isEmpty()) {
                exportArchiveOptionsBuilder.append("<key>teamID</key>\n");
                exportArchiveOptionsBuilder.append("<string>" + exportTeamId + "</string>\n");
            }
            if (exportMethod != null && !exportMethod.isEmpty()) {
                exportArchiveOptionsBuilder.append("<key>method</key>\n");
                exportArchiveOptionsBuilder.append("<string>" + exportMethod + "</string>\n");
            }
            exportArchiveOptionsBuilder.append("</dict>\n");
            exportArchiveOptionsBuilder.append("</plist>\n");
            FilePath exportArchiveOptionsPlist = ipaOutputPath.createTextTempFile("exportOptions", "plist", exportArchiveOptionsBuilder.toString());

            // packaging IPA
            listener.getLogger().println(Messages.XCodeBuilder_packagingIPA());
            List<FilePath> apps = listRecursive(archiveLocation, new AppFileFilter());
            // FilePath is based on File.listFiles() which can randomly fail | http://stackoverflow.com/questions/3228147/retrieving-the-underlying-error-when-file-listfiles-return-null
            if (apps == null) {
                listener.fatalError(Messages.XCodeBuilder_NoAppsInArchiveDirectory(archiveLocation.absolutize().getRemote()));
                return false;
            }

            for (FilePath app : apps) {
                String version = "";
                String shortVersion = "";

                try {
                    output.reset();
                    returnCode = launcher.launch().envs(envs).cmds("/usr/libexec/PlistBuddy", "-c",  "Print :CFBundleVersion", app.absolutize().child("Info.plist").getRemote()).stdout(output).pwd(projectRoot).join();
                    if (returnCode == 0) {
                        version = output.toString().trim();
                    }

                    output.reset();
                    returnCode = launcher.launch().envs(envs).cmds("/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", app.absolutize().child("Info.plist").getRemote()).stdout(output).pwd(projectRoot).join();
                    if (returnCode == 0) {
                        shortVersion = output.toString().trim();
                    }
                }
                catch(Exception ex) {
                    listener.getLogger().println("Failed to get version from Info.plist: " + ex.toString());
                    return false;
                }

               	if (StringUtils.isEmpty(version) && StringUtils.isEmpty(shortVersion)) {
               		listener.getLogger().println("You have to provide a value for either the marketing or technical version. Found neither.");
               		return false;
               	}

                String lastModified = new SimpleDateFormat("yyyy.MM.dd").format(new Date(app.lastModified()));

                String baseName = app.getBaseName().replaceAll(" ", "_") + (shortVersion.isEmpty() ? "" : "-" + shortVersion) + (version.isEmpty() ? "" : "-" + version);
                // If custom .ipa name pattern has been provided, use it and expand version and build date variables
                if (! StringUtils.isEmpty(ipaName)) {
                	EnvVars customVars = new EnvVars(
                		"BASE_NAME", app.getBaseName().replaceAll(" ", "_"),
                		"VERSION", version,
                		"SHORT_VERSION", shortVersion,
                		"BUILD_DATE", lastModified
                	);
                    baseName = customVars.expand(ipaName);
                }

                String ipaFileName = baseName + ".ipa";
                FilePath ipaLocation = ipaOutputPath.child(ipaFileName);
                if (ipaLocation.exists()) {
                    ipaLocation.delete();
                }

                listener.getLogger().println("Packaging " + app.getBaseName() + ".app => " + ipaLocation.absolutize().getRemote());
                if (buildPlatform.contains("simulator")) {
                    listener.getLogger().println(Messages.XCodeBuilder_warningPackagingIPAForSimulatorSDK(sdk));
                }

                // Temporary output path for IPA
                FilePath tempIpaOutputPath = artifactsOutputPath.createTempDir(baseName, ".exportPath");

                List<String> exportCommandLine = new ArrayList<String>();
                exportCommandLine.add(getGlobalConfiguration().getXcodebuildPath());
                exportCommandLine.add("-exportArchive");

                exportCommandLine.add("-archivePath");
                exportCommandLine.add(archiveLocation.absolutize().getRemote());

                exportCommandLine.add("-exportPath");
                exportCommandLine.add(tempIpaOutputPath.absolutize().getRemote());

                exportCommandLine.add("-exportOptionsPlist");
                exportCommandLine.add(exportArchiveOptionsPlist.absolutize().getRemote());

                returnCode = launcher.launch().envs(envs).stdout(listener).pwd(projectRoot).cmds(exportCommandLine).join();
                if (returnCode > 0) {
                    listener.getLogger().println("Failed to build " + ipaLocation.absolutize().getRemote());
                    return false;
                }

                // Move IPA to proper location and cleanup
                tempIpaOutputPath.list(new AnyFileFilter()).get(0).copyTo(ipaLocation);
                tempIpaOutputPath.deleteRecursive();

                // also zip up the symbols, if present
                FilePath dSYMLocation = archiveLocation.child("dSYMs").child(app.getName() + ".dSYM");
                if (dSYMLocation.exists()) {
                    String dSYMZipFileName = baseName + "-dSYM.zip";
                    FilePath dSYMZipLocation = ipaOutputPath.child(dSYMZipFileName);
                    if (dSYMZipLocation.exists()) {
                        dSYMZipLocation.delete();
                    }
                    returnCode = launcher.launch().envs(envs).stdout(listener).pwd(projectRoot).cmds("ditto", "-c", "-k", "--keepParent", "-rsrc", dSYMLocation.absolutize().getRemote(), dSYMZipLocation.absolutize().getRemote()).join();
                    if (returnCode > 0) {
                        listener.getLogger().println(Messages.XCodeBuilder_zipFailed(baseName));
                        return false;
                    }
                }

                if(!StringUtils.isEmpty(ipaManifestPlistUrl)) {
                    FilePath ipaManifestLocation = ipaOutputPath.child(baseName + ".plist");
                    listener.getLogger().println("Creating Manifest Plist => " + ipaManifestLocation.absolutize().getRemote());

                    String displayName = "";
                    String bundleId = "";

                    output.reset();
                    returnCode = launcher.launch().envs(envs).cmds("/usr/libexec/PlistBuddy", "-c", "Print :CFBundleIdentifier", app.absolutize().child("Info.plist").getRemote()).stdout(output).pwd(projectRoot).join();
                    if (returnCode == 0) {
                        bundleId = output.toString().trim();
                    }
                    output.reset();
                    returnCode = launcher.launch().envs(envs).cmds("/usr/libexec/PlistBuddy", "-c", "Print :CFBundleDisplayName", app.absolutize().child("Info.plist").getRemote()).stdout(output).pwd(projectRoot).join();
                    if (returnCode == 0) {
                        displayName = output.toString().trim();
                    }


                    String manifest = MANIFEST_PLIST_TEMPLATE
                                        .replace("${IPA_URL_BASE}", ipaManifestPlistUrl)
                                        .replace("${IPA_NAME}", ipaFileName)
                                        .replace("${BUNDLE_ID}", bundleId)
                                        .replace("${BUNDLE_VERSION}", shortVersion)
                                        .replace("${APP_NAME}", displayName);

                    ipaManifestLocation.write(manifest, "UTF-8");
                }
            }

            // Delete export options file
            exportArchiveOptionsPlist.delete();
        }

        return true;
    }

    public Keychain getKeychain() {
        if(!StringUtils.isEmpty(keychainName)) {
            for (Keychain keychain : getGlobalConfiguration().getKeychains()) {
                if(keychain.getKeychainName().equals(keychainName))
                    return keychain;
            }
        }

        if(!StringUtils.isEmpty(keychainPath)) {
            return new Keychain("", keychainPath, keychainPwd, false);
        }

        return null;
    }

    static List<String> splitXcodeBuildArguments(String xcodebuildArguments) {
        if (xcodebuildArguments == null || xcodebuildArguments.length() == 0) {
            return new ArrayList<String>(0);
        }

        final QuotedStringTokenizer tok = new QuotedStringTokenizer(xcodebuildArguments);
        final List<String> result = new ArrayList<String>();
        while(tok.hasMoreTokens())
            result.add(tok.nextToken());

        return result;
    }

    public GlobalConfigurationImpl getGlobalConfiguration() {
    	return getDescriptor().getGlobalConfiguration();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
    	GlobalConfigurationImpl globalConfiguration;

        // backward compatibility
        @Deprecated
        private transient String xcodebuildPath;
        private transient String agvtoolPath;
        private transient String xcrunPath;
        private transient CopyOnWriteList<Keychain> keychains;

        public DescriptorImpl() {
            load();
        }

        @Inject
        void setGlobalConfiguration(GlobalConfigurationImpl c) {
            this.globalConfiguration = c;
            {// data migration from old format
                boolean modified = false;
                if (xcodebuildPath!=null) {
                    c.setXcodebuildPath(xcodebuildPath);
                    modified = true;
                }
                if (agvtoolPath!=null) {
                    c.setAgvtoolPath(agvtoolPath);
                    modified = true;
                }
                if (xcrunPath!=null) {
                    c.setXcrunPath(xcrunPath);
                    modified = true;
                }
                if (keychains!=null) {
                    c.setKeychains(new ArrayList<Keychain>(keychains.getView()));
                    modified = true;
                }
                if (modified) {
                    c.save();
                    save(); // delete the old values from the disk now that the new values are committed
                }
            }
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @Override
		public String getDisplayName() {
			return Messages.XCodeBuilder_xcode();
		}

	    public GlobalConfigurationImpl getGlobalConfiguration() {
	    	return globalConfiguration;
	    }

	    public String getUUID() {
	    	return "" + UUID.randomUUID().getMostSignificantBits();
	    }
    }
}
