using System.Threading.Tasks;
using GraphQL.Language.AST;
using GraphQL.Types;
using GraphQL.Validation;

namespace GraphQL.Authorization
{
    internal static class TaskHelper
    {
        public static Task<INodeVisitor> ToTask(this INodeVisitor visitor) => Task.FromResult(visitor);
    }

    /// <summary>
    ///
    /// </summary>
    public class AuthorizationValidationRule : IValidationRule
    {
        private readonly IAuthorizationEvaluator _evaluator;

        /// <summary>
        ///
        /// </summary>
        /// <param name="evaluator"></param>
        public AuthorizationValidationRule(IAuthorizationEvaluator evaluator)
        {
            _evaluator = evaluator;
        }

        public Task<INodeVisitor> ValidateAsync(ValidationContext context)
        {
            var userContext = context.UserContext as IProvideClaimsPrincipal;

            var operationType = OperationType.Query;
            return new NodeVisitors(
                new MatchingNodeVisitor<Operation>((node, context) =>
                {
                    operationType = node.OperationType;
                    var type = context.TypeInfo.GetLastType();
                    CheckAuth(node, type, userContext, context, node.OperationType);
                }),
                new MatchingNodeVisitor<ObjectField>((node, context) =>
                {
                    if (context.TypeInfo.GetArgument()?.ResolvedType.GetNamedType() is IComplexGraphType argumentType)
                    {
                        var fieldType = argumentType.GetField(node.Name);
                        CheckAuth(node, fieldType, userContext, context, operationType);
                    }
                }),
                new MatchingNodeVisitor<Field>((node, context) =>
                {
                    var fieldDef = context.TypeInfo.GetFieldDef();

                    if (fieldDef == null)
                        return;

                    // check target field
                    CheckAuth(node, fieldDef, userContext, context, operationType);
                    // check returned graph type
                    CheckAuth(node, fieldDef.ResolvedType.GetNamedType(), userContext, context, operationType);
                })
            ).ToTask();
        }


        private void CheckAuth(
            INode node,
            IProvideMetadata type,
            IProvideClaimsPrincipal? userContext,
            ValidationContext context,
            OperationType operationType)
        {
            if (type == null || !AuthorizationExtensions.RequiresAuthorization(type))
                return;

            // TODO: async -> sync transition
            var result = type
                .Authorize(userContext?.User, context.UserContext, context.Inputs, _evaluator)
                .GetAwaiter()
                .GetResult();

            if (result.Succeeded)
                return;

            string errors = string.Join("\n", result.Errors);

            context.ReportError(new ValidationError(
                context.Document.OriginalQuery,
                "authorization",
                $"You are not authorized to run this {operationType.ToString().ToLower()}.\n{errors}",
                node));
        }
    }
}
