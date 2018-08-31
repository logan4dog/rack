package cli_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/convox/rack/pkg/cli"
	mocksdk "github.com/convox/rack/pkg/mock/sdk"
	"github.com/convox/rack/pkg/options"
	"github.com/convox/rack/pkg/structs"
	"github.com/convox/rack/provider"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var fxSystem = structs.System{
	Count:      1,
	Domain:     "domain",
	Name:       "name",
	Outputs:    map[string]string{"k1": "v1", "k2": "v2"},
	Parameters: map[string]string{"Autoscale": "Yes", "ParamFoo": "value1", "ParamOther": "value2"},
	Provider:   "provider",
	Region:     "region",
	Status:     "running",
	Type:       "type",
	Version:    "20180901000000",
}

var fxSystemClassic = structs.System{
	Count:      1,
	Domain:     "domain",
	Name:       "name",
	Outputs:    map[string]string{"k1": "v1", "k2": "v2"},
	Parameters: map[string]string{"ParamFoo": "value1", "ParamOther": "value2"},
	Provider:   "provider",
	Region:     "region",
	Status:     "running",
	Type:       "type",
	Version:    "20180101000000",
}

func TestRack(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)

		res, err := testExecute(e, "rack", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"Name     name",
			"Status   running",
			"Version  20180901000000",
			"Region   region",
			"Router   domain",
		})
	})
}

func TestRackError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackInstall(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "/auth", r.URL.Path)
			user, pass, _ := r.BasicAuth()
			require.Equal(t, "convox", user)
			require.Equal(t, "password", pass)
		}))

		tsu, err := url.Parse(ts.URL)
		require.NoError(t, err)

		tmp, err := ioutil.TempDir("", "")
		require.NoError(t, err)
		e.Settings = tmp

		opts := structs.SystemInstallOptions{
			Name:       options.String("foo"),
			Parameters: map[string]string{},
			Version:    options.String("bar"),
		}
		provider.Mock.On("SystemInstall", mock.Anything, opts).Once().Return(fmt.Sprintf("https://convox:password@%s", tsu.Host), nil).Run(func(args mock.Arguments) {
			w := args.Get(0).(io.Writer)
			fmt.Fprintf(w, "line1\n")
			fmt.Fprintf(w, "line2\n")
		})

		res, err := testExecute(e, "rack install test -n foo -v bar", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"line1",
			"line2",
			fmt.Sprintf("Authenticating with %s... OK", tsu.Host),
		})

		data, err := ioutil.ReadFile(filepath.Join(tmp, "auth"))
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("{\n  \"%s\": \"password\"\n}", tsu.Host), string(data))

		data, err = ioutil.ReadFile(filepath.Join(tmp, "host"))
		require.NoError(t, err)
		require.Equal(t, tsu.Host, string(data))
	})
}

func TestRackInstallError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		opts := structs.SystemInstallOptions{
			Name:       options.String("foo"),
			Parameters: map[string]string{},
			Version:    options.String("bar"),
		}
		provider.Mock.On("SystemInstall", mock.Anything, opts).Return("", fmt.Errorf("err1"))

		res, err := testExecute(e, "rack install test -n foo -v bar", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackLogs(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemLogs", structs.LogsOptions{}).Return(testLogs(fxLogs), nil)

		res, err := testExecute(e, "rack logs", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			fxLogs[0],
			fxLogs[1],
		})
	})
}

func TestRackLogsError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemLogs", structs.LogsOptions{}).Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack logs", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackParams(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)

		res, err := testExecute(e, "rack params", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"Autoscale   Yes",
			"ParamFoo    value1",
			"ParamOther  value2",
		})
	})
}

func TestRackParamsError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack params", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackParamsSet(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)
		opts := structs.SystemUpdateOptions{
			Parameters: map[string]string{
				"Foo": "bar",
				"Baz": "qux",
			},
		}
		i.On("SystemUpdate", opts).Return(nil)

		res, err := testExecute(e, "rack params set Foo=bar Baz=qux", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{"Updating parameters... OK"})
	})
}

func TestRackParamsSetError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)
		opts := structs.SystemUpdateOptions{
			Parameters: map[string]string{
				"Foo": "bar",
				"Baz": "qux",
			},
		}
		i.On("SystemUpdate", opts).Return(fmt.Errorf("err1"))

		res, err := testExecute(e, "rack params set Foo=bar Baz=qux", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{"Updating parameters... "})
	})
}

func TestRackParamsSetClassic(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystemClassic, nil)
		i.On("AppParametersSet", "name", map[string]string{"Foo": "bar", "Baz": "qux"}).Return(nil)

		res, err := testExecute(e, "rack params set Foo=bar Baz=qux", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{"Updating parameters... OK"})
	})
}

func TestRackParamsSetClassicError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystemClassic, nil)
		i.On("AppParametersSet", "name", map[string]string{"Foo": "bar", "Baz": "qux"}).Return(fmt.Errorf("err1"))

		res, err := testExecute(e, "rack params set Foo=bar Baz=qux", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{"Updating parameters... "})
	})
}

func TestRackPs(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemProcesses", structs.SystemProcessesOptions{}).Return(structs.Processes{fxProcess, fxProcess}, nil)

		res, err := testExecute(e, "rack ps", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"ID    APP   SERVICE  STATUS  RELEASE   STARTED     COMMAND",
			"pid1  app1  name     status  release1  2 days ago  command",
			"pid1  app1  name     status  release1  2 days ago  command",
		})
	})
}

func TestRackPsError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemProcesses", structs.SystemProcessesOptions{}).Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack ps", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackPsAll(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemProcesses", structs.SystemProcessesOptions{All: options.Bool(true)}).Return(structs.Processes{fxProcess, fxProcess}, nil)

		res, err := testExecute(e, "rack ps -a", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"ID    APP   SERVICE  STATUS  RELEASE   STARTED     COMMAND",
			"pid1  app1  name     status  release1  2 days ago  command",
			"pid1  app1  name     status  release1  2 days ago  command",
		})
	})
}

func TestRackReleases(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemReleases").Return(structs.Releases{fxRelease, fxRelease}, nil)

		res, err := testExecute(e, "rack releases", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"VERSION   UPDATED   ",
			"release1  2 days ago",
			"release1  2 days ago",
		})
	})
}

func TestRackReleasesError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemReleases").Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack releases", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackScale(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)

		res, err := testExecute(e, "rack scale", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"Autoscale  Yes",
			"Count      1",
			"Status     running",
			"Type       type",
		})
	})
}

func TestRackScaleError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack scale", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{""})
	})
}

func TestRackScaleUpdate(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)
		i.On("SystemUpdate", structs.SystemUpdateOptions{Count: options.Int(5), Type: options.String("type1")}).Return(nil)

		res, err := testExecute(e, "rack scale -c 5 -t type1", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{"Scaling rack... OK"})
	})
}

func TestRackScaleUpdateError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemGet").Return(&fxSystem, nil)
		i.On("SystemUpdate", structs.SystemUpdateOptions{Count: options.Int(5), Type: options.String("type1")}).Return(fmt.Errorf("err1"))

		res, err := testExecute(e, "rack scale -c 5 -t type1", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{"Scaling rack... "})
	})
}

func TestRackUpdate(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemUpdate", structs.SystemUpdateOptions{Version: options.String("version1")}).Return(nil)

		res, err := testExecute(e, "rack update version1", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{"Updating to version1... OK"})
	})
}

func TestRackUpdateError(t *testing.T) {
	testClient(t, func(e *cli.Engine, i *mocksdk.Interface) {
		i.On("SystemUpdate", structs.SystemUpdateOptions{Version: options.String("version1")}).Return(fmt.Errorf("err1"))

		res, err := testExecute(e, "rack update version1", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{"Updating to version1... "})
	})
}

func TestRackWait(t *testing.T) {
	testClientWait(t, 100*time.Millisecond, func(e *cli.Engine, i *mocksdk.Interface) {
		opts := structs.LogsOptions{
			Prefix: options.Bool(true),
			Since:  options.Duration(0),
		}
		i.On("SystemLogs", opts).Return(testLogs(fxLogsSystem), nil).Once()
		i.On("SystemGet").Return(&structs.System{Status: "updating"}, nil).Twice()
		i.On("SystemGet").Return(&fxSystem, nil)

		res, err := testExecute(e, "rack wait", nil)
		require.NoError(t, err)
		require.Equal(t, 0, res.Code)
		res.RequireStderr(t, []string{""})
		res.RequireStdout(t, []string{
			"Waiting for rack... ",
			fxLogsSystem[0],
			fxLogsSystem[1],
			"OK",
		})
	})
}

func TestRackWaitError(t *testing.T) {
	testClientWait(t, 100*time.Millisecond, func(e *cli.Engine, i *mocksdk.Interface) {
		opts := structs.LogsOptions{
			Prefix: options.Bool(true),
			Since:  options.Duration(0),
		}
		i.On("SystemLogs", opts).Return(testLogs(fxLogsSystem), nil).Once()
		i.On("SystemGet").Return(nil, fmt.Errorf("err1"))

		res, err := testExecute(e, "rack wait", nil)
		require.NoError(t, err)
		require.Equal(t, 1, res.Code)
		res.RequireStderr(t, []string{"ERROR: err1"})
		res.RequireStdout(t, []string{
			"Waiting for rack... ",
			fxLogsSystem[0],
			fxLogsSystem[1],
		})
	})
}