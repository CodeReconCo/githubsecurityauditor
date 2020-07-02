/*
Copyright © 2020 Mike de Libero

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-github/v31/github"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"io/ioutil"
	"os"
	"time"
)

type ScannerResults struct {
	TwoFactorAuthEnabled bool
	NumberPrivateRepos   int
	NumberPublicRepos    int
	Webhooks             []Webhook
	// ThirdPartyApps - ListInstallations
	// ActionPermisions
}

type Webhook struct {
	URL    string
	Active bool
}

type GithubScanner struct {
	client *github.Client
}

var cfgFile string
var Organization string
var OutputFile string
var ScmURL string
var TokenName string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "githubsecurityauditor",
	Short: "A tool to collect and highlight potential security issues with a GitHub org",
	Long: `A tool to collect and highlight potential security issues with a GitHub org. It looks 
	at things like:
	* Webhooks
	* User configuration
	* Number of guests
	* Repo and Organization-level settings`,
	Run: func(cmd *cobra.Command, args []string) {
		scanner := GithubScanner{}
		scanner.runScan()
	},
}

func (gs GithubScanner) RetrieveOrgWebhooks(ctx context.Context, org *string) []Webhook {
	var webhooks []Webhook
	opt := &github.ListOptions{PerPage: 10}
	for {
		hooks, resp, err := gs.client.Organizations.ListHooks(ctx, *org, opt)

		if err != nil {
			fmt.Println(err)
			return webhooks
		}

		if _, ok := err.(*github.RateLimitError); ok {
			fmt.Println("Hit rate limit, sleeping for sixty minutes")
			time.Sleep(60 * time.Minute)
		}

		for _, hook := range hooks {
			wh := Webhook{}
			wh.URL = hook.Config["url"].(string)
			wh.Active = *hook.Active
			webhooks = append(webhooks, wh)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return webhooks
}

func (gs GithubScanner) RetrieveOrgSettings(ctx context.Context, org *string, results ScannerResults) ScannerResults {
	orgInfo, _, err := gs.client.Organizations.Get(ctx, *org)

	if err != nil {
		fmt.Println(err)
		return results
	}
	results.TwoFactorAuthEnabled = *orgInfo.TwoFactorRequirementEnabled
	results.NumberPublicRepos = *orgInfo.PublicRepos
	results.NumberPrivateRepos = *orgInfo.TotalPrivateRepos
	results.Webhooks = gs.RetrieveOrgWebhooks(ctx, org)

	return results
}

func (gs GithubScanner) runScan() {
	token := os.Getenv(TokenName)
	if token == "" {
		fmt.Println(TokenName + " is empty")
		return
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	if ScmURL != "" {
		var clientErr error
		gs.client, clientErr = github.NewEnterpriseClient(ScmURL, ScmURL, tc)

		if clientErr != nil {
			fmt.Println(clientErr)
			return
		}
	} else {
		gs.client = github.NewClient(tc)
	}
	var results ScannerResults

	// * Org Settings
	//    * Webhooks
	//    * 2fa required
	//    * Third-party applications - policy is not access restricted
	//    * Action permissions
	//        * Disable actions for this organization
	//    * Number of public repos
	//    * Number of private repos
	//    TODO: Test with an invalid org and one we don't own
	results = gs.RetrieveOrgSettings(ctx, &Organization, results)

	output, _ := json.MarshalIndent(results, "", " ")
	_ = ioutil.WriteFile(OutputFile, output, 0644)
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.Flags().StringVarP(&cfgFile, "config", "", "", "config file (default is $HOME/.githubsecurityauditor.yaml)")
	rootCmd.Flags().StringVarP(&Organization, "organization", "", "", "The organization we want to check the security on")
	rootCmd.Flags().StringVarP(&OutputFile, "output", "", "githubsecurity.json", "The file that should have the output recorded to")
	rootCmd.Flags().StringVarP(&ScmURL, "scmUrl", "", "", "The API URL for the source control management software you want to check")
	rootCmd.Flags().StringVarP(&TokenName, "tokenName", "", "GIT_TOKEN", "The environment variable name we should retrieve the token for API authentication")

	rootCmd.MarkFlagRequired("organization")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".githubsecurityauditor" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".githubsecurityauditor")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
